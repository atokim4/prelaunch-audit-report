create table public.audit_events (
  id bigint generated always as identity primary key,
  organization_id uuid not null references public.organizations (id) on delete cascade,
  actor_id uuid not null references auth.users (id) default auth.uid(),
  action text not null,
  created_at timestamptz not null default now()
);

alter table public.audit_events enable row level security;

create policy "Members can read their audit trail"
  on public.audit_events for select
  to authenticated
  using (public.is_member(organization_id));

create policy "Members can write their own events"
  on public.audit_events for insert
  to authenticated
  with check (public.is_member(organization_id) and actor_id = (select auth.uid()));
