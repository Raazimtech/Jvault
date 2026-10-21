-- JVault schema and private-storage policies.
create extension if not exists pgcrypto;

create table if not exists public.jvault_bootstrap_state (
  id integer primary key check (id = 1),
  claimed boolean not null default false,
  created_at timestamptz not null default now()
);
insert into public.jvault_bootstrap_state (id, claimed) values (1, false) on conflict (id) do nothing;
alter table public.jvault_bootstrap_state enable row level security;

create table if not exists public.jvault_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  created_at timestamptz not null default now(),
  constraint jvault_username_format check (username ~ '^[a-zA-Z0-9_]{3,24}$')
);
alter table public.jvault_profiles enable row level security;
drop policy if exists "JVault users can read own profile" on public.jvault_profiles;
create policy "JVault users can read own profile" on public.jvault_profiles
for select to authenticated using (user_id = auth.uid());

create table if not exists public.jvault_files (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 255),
  storage_path text not null unique,
  size_bytes bigint not null default 0 check (size_bytes >= 0),
  mime_type text not null default 'application/octet-stream',
  category text not null default 'Uncategorized' check (char_length(category) between 1 and 40),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists jvault_files_owner_created_idx on public.jvault_files (owner_id, created_at desc);
create index if not exists jvault_files_owner_category_idx on public.jvault_files (owner_id, category);
alter table public.jvault_files enable row level security;
drop policy if exists "JVault owners manage their file records" on public.jvault_files;
create policy "JVault owners manage their file records" on public.jvault_files
for all to authenticated using (
  owner_id = auth.uid() and exists (select 1 from public.jvault_profiles p where p.user_id = auth.uid())
) with check (
  owner_id = auth.uid() and exists (select 1 from public.jvault_profiles p where p.user_id = auth.uid())
);

insert into storage.buckets (id, name, public, file_size_limit)
values ('jvault-private', 'jvault-private', false, 52428800)
on conflict (id) do update set public = false, file_size_limit = 52428800;

drop policy if exists "JVault users read own objects" on storage.objects;
create policy "JVault users read own objects" on storage.objects for select to authenticated using (
  bucket_id = 'jvault-private' and (storage.foldername(name))[1] = auth.uid()::text
  and exists (select 1 from public.jvault_profiles p where p.user_id = auth.uid())
);
drop policy if exists "JVault users upload own objects" on storage.objects;
create policy "JVault users upload own objects" on storage.objects for insert to authenticated with check (
  bucket_id = 'jvault-private' and (storage.foldername(name))[1] = auth.uid()::text
  and exists (select 1 from public.jvault_profiles p where p.user_id = auth.uid())
);
drop policy if exists "JVault users update own objects" on storage.objects;
create policy "JVault users update own objects" on storage.objects for update to authenticated using (
  bucket_id = 'jvault-private' and (storage.foldername(name))[1] = auth.uid()::text
  and exists (select 1 from public.jvault_profiles p where p.user_id = auth.uid())
) with check (
  bucket_id = 'jvault-private' and (storage.foldername(name))[1] = auth.uid()::text
  and exists (select 1 from public.jvault_profiles p where p.user_id = auth.uid())
);
drop policy if exists "JVault users delete own objects" on storage.objects;
create policy "JVault users delete own objects" on storage.objects for delete to authenticated using (
  bucket_id = 'jvault-private' and (storage.foldername(name))[1] = auth.uid()::text
  and exists (select 1 from public.jvault_profiles p where p.user_id = auth.uid())
);
