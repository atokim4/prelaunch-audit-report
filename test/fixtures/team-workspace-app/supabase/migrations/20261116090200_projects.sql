create table public.projects (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  name text not null,
  created_by uuid references auth.users (id) default auth.uid(),
  created_at timestamptz not null default now()
);

alter table public.projects enable row level security;

create policy "Members can manage projects"
  on public.projects for all
  to authenticated
  using (exists (select 1 from public.organization_members m where m.user_id = (select auth.uid())));

create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects (id) on delete cascade,
  title text not null,
  done boolean not null default false
);

alter table public.tasks enable row level security;

create policy "Members can manage tasks"
  on public.tasks for all
  to authenticated
  using (exists (select 1 from public.projects p where p.id = tasks.project_id and public.is_member(p.organization_id)))
  with check (exists (select 1 from public.projects p where p.id = tasks.project_id and public.is_member(p.organization_id)));
