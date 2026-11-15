create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title text not null,
  done boolean not null default false,
  due_on date
);

alter table public.tasks enable row level security;

create policy "Users can read their tasks"
  on public.tasks for select
  to authenticated
  using ((select auth.uid()) = owner_id);

create policy "Users can add their tasks"
  on public.tasks for insert
  to authenticated
  with check ((select auth.uid()) = owner_id);

create policy "Users can update their tasks"
  on public.tasks for update
  to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);

create policy "Users can delete their tasks"
  on public.tasks for delete
  to authenticated
  using ((select auth.uid()) = owner_id);

create view public.open_tasks
  with (security_invoker = true)
  as select id, owner_id, title, due_on from public.tasks where not done;
