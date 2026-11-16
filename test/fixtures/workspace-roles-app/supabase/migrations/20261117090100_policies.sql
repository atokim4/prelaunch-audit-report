alter table public.workspaces enable row level security;
alter table public.roles enable row level security;
alter table public.workspace_users enable row level security;
alter table public.documents enable row level security;
alter table public.projects enable row level security;

create policy "members read their workspace" on public.workspaces
  for select to authenticated using (public.is_workspace_member(id));

-- Role names are the same for everyone.
create policy "signed-in users read roles" on public.roles
  for select to authenticated using (true);

create policy "members read their workspace's members" on public.workspace_users
  for select to authenticated using (public.is_workspace_member(workspace_id));

create policy "users join a workspace" on public.workspace_users
  for insert to authenticated with check (user_id = (select auth.uid()));

create policy "users edit their own membership" on public.workspace_users
  for update to authenticated using (user_id = (select auth.uid()));

create policy "signed-in users read documents" on public.documents
  for select to authenticated using (true);

create policy "members add documents" on public.documents
  for insert to authenticated with check (public.is_workspace_member(workspace_id));

create policy "members read projects" on public.projects
  for select to authenticated using (public.is_workspace_member(workspace_id));

create policy "members add projects" on public.projects
  for insert to authenticated with check (public.is_workspace_member(workspace_id));

create policy "members edit projects" on public.projects
  for update to authenticated
  using (public.is_workspace_member(workspace_id))
  with check (public.is_workspace_member(workspace_id));
