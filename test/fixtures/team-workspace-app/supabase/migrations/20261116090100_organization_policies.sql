alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;

create policy "Members can view their organization"
  on public.organizations for select
  to authenticated
  using (public.is_member(id));

create policy "Signed-in users can create organizations"
  on public.organizations for insert
  to authenticated
  with check ((select auth.uid()) is not null);

create policy "Members can update their organization"
  on public.organizations for update
  to authenticated
  using (public.is_member(id));

create policy "Members can view their team"
  on public.organization_members for select
  to authenticated
  using (public.is_member(organization_id));

create policy "Users can join organizations"
  on public.organization_members for insert
  to authenticated
  with check (user_id = (select auth.uid()));

create policy "Users can update their membership"
  on public.organization_members for update
  to authenticated
  using (user_id = (select auth.uid()));

create policy "Users can leave organizations"
  on public.organization_members for delete
  to authenticated
  using (user_id = (select auth.uid()));
