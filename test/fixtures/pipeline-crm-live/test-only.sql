-- Extra objects for the live-probe tests only (not in the sample): a table the API roles have no
-- grant on, so PostgREST answers 42501, and a child table owned only through its parent row.
create table public.audit_log (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users (id),
  action text not null
);
revoke all on public.audit_log from anon, authenticated;

create table public.lead_files (
  id uuid primary key default gen_random_uuid(),
  lead_id uuid not null references public.leads (id) on delete cascade,
  label text not null
);
alter table public.lead_files enable row level security;
create policy "Anyone signed in can read lead files"
  on public.lead_files for select
  to authenticated
  using (true);
insert into public.lead_files (lead_id, label)
  select id, 'Sample file' from public.leads where name in ('Sample lead 1', 'Sample lead 3');
