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


-- Row security: profiles are managed only by the admin-users Edge Function.
alter table public.records enable row level security;
alter table public.profiles enable row level security;
revoke all on public.records, public.profiles from anon;
revoke insert,update,delete,truncate,references,trigger on public.profiles from authenticated;
grant select on public.profiles to authenticated;
grant select,insert,update,delete on public.records to authenticated;
drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles for select to authenticated using(user_id=(select auth.uid()));
drop policy if exists "permitted reads" on public.records;
drop policy if exists "permitted inserts" on public.records;
drop policy if exists "permitted updates" on public.records;
drop policy if exists "permitted deletes" on public.records;

drop policy if exists "staff full access" on public.records;
create policy "permitted reads" on public.records for select to authenticated using (
 exists(select 1 from public.profiles p where p.user_id=(select auth.uid()) and
 (p.role='admin' or collection='settings' or p.permissions && case collection
 when 'products' then array['products','orders','invoices']
 when 'inventory' then array['inventory','products']
 when 'customers' then array['customers','orders','invoices']
 when 'orders' then array['orders','invoices']
 when 'income' then array['finance','orders']
 when 'expenses' then array['finance']
 when 'invoices' then array['invoices']
 when 'reminders' then array['reminders']
 when 'failedPrints' then array['orders']
 when 'calc' then array['products']
 else array[]::text[] end))
);
create policy "permitted inserts" on public.records for insert to authenticated with check (exists(select 1 from public.profiles p where p.user_id=(select auth.uid()) and
(p.role='admin' or p.permissions && case collection
 when 'products' then array['products','orders']
 when 'inventory' then array['inventory']
 when 'customers' then array['customers']
 when 'orders' then array['orders']
 when 'income' then array['finance','orders']
 when 'expenses' then array['finance']
 when 'invoices' then array['invoices']
 when 'reminders' then array['reminders']
 when 'failedPrints' then array['orders']
 when 'settings' then array['settings']
 when 'calc' then array['products']
 else array[]::text[] end)));
create policy "permitted updates" on public.records for update to authenticated using (exists(select 1 from public.profiles p where p.user_id=(select auth.uid()) and
(p.role='admin' or p.permissions && case collection
 when 'products' then array['products','orders']
 when 'inventory' then array['inventory']
 when 'customers' then array['customers']
 when 'orders' then array['orders']
 when 'income' then array['finance','orders']
 when 'expenses' then array['finance']
 when 'invoices' then array['invoices']
 when 'reminders' then array['reminders']
 when 'failedPrints' then array['orders']
 when 'settings' then array['settings']
 when 'calc' then array['products']
 else array[]::text[] end))) with check (exists(select 1 from public.profiles p where p.user_id=(select auth.uid()) and
(p.role='admin' or p.permissions && case collection
 when 'products' then array['products','orders']
 when 'inventory' then array['inventory']
 when 'customers' then array['customers']
 when 'orders' then array['orders']
 when 'income' then array['finance','orders']
 when 'expenses' then array['finance']
 when 'invoices' then array['invoices']
 when 'reminders' then array['reminders']
 when 'failedPrints' then array['orders']
 when 'settings' then array['settings']
 when 'calc' then array['products']
 else array[]::text[] end)));
create policy "permitted deletes" on public.records for delete to authenticated using (exists(select 1 from public.profiles p where p.user_id=(select auth.uid()) and
(p.role='admin' or p.permissions && case collection
 when 'products' then array['products','orders']
 when 'inventory' then array['inventory']
 when 'customers' then array['customers']
 when 'orders' then array['orders']
 when 'income' then array['finance','orders']
 when 'expenses' then array['finance']
 when 'invoices' then array['invoices']
 when 'reminders' then array['reminders']
 when 'failedPrints' then array['orders']
 when 'settings' then array['settings']
 when 'calc' then array['products']
 else array[]::text[] end)));
-- Create the initial admin AFTER creating their account in Authentication > Users:
-- insert into public.profiles(user_id,name,role,permissions)
-- select id,'Alaa','admin',array['all']::text[] from auth.users where email='YOUR_ADMIN_EMAIL';
-- Other users are created and edited through the Users page.
