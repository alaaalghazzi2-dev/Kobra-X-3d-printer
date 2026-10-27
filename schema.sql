-- 3Dzone Manager — Supabase / PostgreSQL schema
-- Run once in: Supabase Dashboard > SQL Editor > New query > Run

-- 1) All business data (products, orders, invoices, ...) — one row per record
create table if not exists public.records (
  collection text        not null,
  id         bigint      not null,
  data       jsonb       not null,
  updated_at timestamptz not null default now(),
  primary key (collection, id)
);

-- 2) Who is allowed in, and with what role
create table if not exists public.profiles (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  name        text,
  role        text not null default 'staff' check (role in ('admin', 'staff')),
  permissions text[] not null default '{}'   -- for staff, e.g. {products,orders,customers}
);

-- 3) Row Level Security: nobody can touch the data without a profile row
alter table public.records  enable row level security;
alter table public.profiles enable row level security;

create or replace function public.is_staff() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where user_id = auth.uid());
$$;

drop policy if exists "staff full access" on public.records;
create policy "staff full access" on public.records
  for all to authenticated
  using (public.is_staff()) with check (public.is_staff());

drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles
  for select to authenticated
  using (user_id = auth.uid());

-- 4) After creating your user in Authentication > Users, make yourself admin
--    (replace the UUID with the one shown next to your user, and the name):
-- insert into public.profiles (user_id, name, role)
 values ('991347de-eb6f-4f54-be58-6d9064e5bd6f', 'Alaa', 'admin');
--
-- Add a staff member limited to some sections:
-- insert into public.profiles (user_id, name, role, permissions)
 values ('991347de-eb6f-4f54-be58-6d9064e5bd6f', 'Lama', 'staff', '{products,orders,customers}');
