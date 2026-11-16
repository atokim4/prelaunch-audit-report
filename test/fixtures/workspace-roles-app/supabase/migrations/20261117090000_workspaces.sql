-- Workspaces, a roles lookup table and the membership table that points at it.
create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table public.roles (
  id smallint generated always as identity primary key,
  name text not null unique
);
insert into public.roles (name) values ('owner'), ('admin'), ('member');

create table public.workspace_users (
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role_id smallint not null references public.roles (id),
  primary key (workspace_id, user_id)
);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  title text not null,
  body text not null default ''
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces (id) on delete cascade,
  name text not null
);

create function public.is_workspace_member(target uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.workspace_users wu
    where wu.workspace_id = target and wu.user_id = (select auth.uid())
  );
$$;
revoke execute on function public.is_workspace_member(uuid) from public, anon;
grant execute on function public.is_workspace_member(uuid) to authenticated;
