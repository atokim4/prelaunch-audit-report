-- Private notes. Each user can only see and change their own.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title text not null,
  body text not null default '',
  created_at timestamptz not null default now()
);

create index notes_user_id_idx on public.notes (user_id);

alter table public.notes enable row level security;

create policy "Owners can read their notes"
  on public.notes for select
  to authenticated
  using ((select auth.uid()) = user_id);

create policy "Owners can create notes"
  on public.notes for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

create policy "Owners can edit their notes"
  on public.notes for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "Owners can delete their notes"
  on public.notes for delete
  to authenticated
  using ((select auth.uid()) = user_id);
