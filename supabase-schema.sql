-- ============================================================
-- StudyHub — Supabase setup script
-- Paste this whole file into Supabase Dashboard → SQL Editor → New query
-- → Run. It's safe to run once on a brand-new project.
-- ============================================================

create extension if not exists pgcrypto;

-- ---------- profiles (one row per account) ----------
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  name text not null default '',
  bio text not null default '',
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

-- ---------- documents (the shared library) ----------
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  is_example boolean not null default false,
  curric_track text,
  curric_level text,
  curric_subject text,
  pages jsonb not null default '[]'::jsonb,
  file_name text,
  file_path text,
  preview_unavailable boolean not null default false,
  uploaded_by uuid references auth.users(id) on delete set null,
  uploaded_at timestamptz not null default now()
);

-- ---------- saved_docs (each reader's own library) ----------
create table public.saved_docs (
  user_id uuid references auth.users(id) on delete cascade,
  document_id uuid references public.documents(id) on delete cascade,
  saved_at timestamptz not null default now(),
  primary key (user_id, document_id)
);

-- ---------- document_views (powers the hourly blur feature) ----------
create table public.document_views (
  id bigint generated always as identity primary key,
  document_id uuid references public.documents(id) on delete cascade,
  viewed_by uuid references auth.users(id) on delete cascade,
  viewed_at timestamptz not null default now()
);

-- ---------- security_log (admin-only activity feed) ----------
create table public.security_log (
  id bigint generated always as identity primary key,
  message text not null,
  actor_email text,
  created_at timestamptz not null default now()
);

-- ============================================================
-- New signup → profile row. The very first account ever created
-- becomes the admin automatically; everyone after that is a regular
-- reader unless you promote them later (see the note at the bottom).
-- ============================================================
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  first_user boolean;
begin
  select count(*) = 0 into first_user from public.profiles;
  insert into public.profiles (id, email, name, is_admin)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    first_user
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Lets policies below check "is this the admin?" without re-querying
-- profiles from inside a profiles policy (which Postgres won't allow).
create or replace function public.is_admin()
returns boolean
language sql stable security definer set search_path = public
as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;

-- ============================================================
-- Row Level Security — every table below is closed by default;
-- these policies are the only doors in.
-- ============================================================
alter table public.profiles enable row level security;
alter table public.documents enable row level security;
alter table public.saved_docs enable row level security;
alter table public.document_views enable row level security;
alter table public.security_log enable row level security;

create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = id);
create policy "profiles_update_own" on public.profiles
  for update using (auth.uid() = id);

create policy "documents_select_authenticated" on public.documents
  for select using (auth.role() = 'authenticated');
create policy "documents_insert_admin" on public.documents
  for insert with check (public.is_admin());
create policy "documents_update_admin" on public.documents
  for update using (public.is_admin());
create policy "documents_delete_admin" on public.documents
  for delete using (public.is_admin());

create policy "saved_select_own" on public.saved_docs
  for select using (auth.uid() = user_id);
create policy "saved_insert_own" on public.saved_docs
  for insert with check (auth.uid() = user_id);
create policy "saved_delete_own" on public.saved_docs
  for delete using (auth.uid() = user_id);

create policy "views_insert_own" on public.document_views
  for insert with check (auth.uid() = viewed_by);
create policy "views_select_authenticated" on public.document_views
  for select using (auth.role() = 'authenticated');

create policy "log_insert_authenticated" on public.security_log
  for insert with check (auth.role() = 'authenticated');
create policy "log_select_admin" on public.security_log
  for select using (public.is_admin());

-- ============================================================
-- Storage bucket for the actual uploaded files (any file type).
-- If this INSERT errors on your project, just create it by hand instead:
-- Dashboard → Storage → New bucket → name it "documents" → Public: OFF.
-- ============================================================
insert into storage.buckets (id, name, public)
values ('documents', 'documents', false)
on conflict (id) do nothing;

create policy "storage_read_authenticated" on storage.objects
  for select using (bucket_id = 'documents' and auth.role() = 'authenticated');
create policy "storage_insert_admin" on storage.objects
  for insert with check (bucket_id = 'documents' and public.is_admin());
create policy "storage_delete_admin" on storage.objects
  for delete using (bucket_id = 'documents' and public.is_admin());

-- ============================================================
-- Done. To hand admin to someone else later (e.g. you signed up on a
-- test email first by accident), run:
--   update public.profiles set is_admin = false where email = 'old@example.com';
--   update public.profiles set is_admin = true  where email = 'new@example.com';
-- ============================================================
