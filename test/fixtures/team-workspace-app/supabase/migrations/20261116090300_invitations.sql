create table public.invitations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  email text not null,
  role text not null check (role in ('admin', 'member')),
  token text not null unique default replace(gen_random_uuid()::text, '-', ''),
  invited_by uuid references auth.users (id) default auth.uid(),
  created_at timestamptz not null default now()
);

alter table public.invitations enable row level security;

-- The accept page looks the invite up by token before the user is a member.
create policy "Invites are readable by signed-in users"
  on public.invitations for select
  to authenticated
  using (true);

create policy "Members can invite"
  on public.invitations for insert
  to authenticated
  with check (public.is_member(organization_id));
