-- Changes "made in the Supabase dashboard" on the stand-in project and never saved as migrations.
-- Applied after the app's migrations and before seed.sql, so the live probe has drift to find.

-- 1. Someone fixed the open leads policy by hand (the migrations still have the hole).
drop policy "Enable read access for all users" on public.leads;
create policy "Owners can read their leads"
  on public.leads for select
  to authenticated
  using (auth.uid() = owner_id);

-- 2. Someone opened tasks to the whole team by hand (the migrations keep users apart).
create policy "Team can read tasks"
  on public.tasks for select
  to authenticated
  using (true);

-- 3. A table created in the table editor: only the generated types know it.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  lead_id uuid references public.leads (id) on delete set null,
  body text not null,
  created_at timestamptz not null default now()
);
alter table public.notes enable row level security;
create policy "Users read their notes"
  on public.notes for select
  to authenticated
  using (auth.uid() = user_id);

-- 4. A private bucket for attachments with a read policy that checks the bucket, not the folder.
insert into storage.buckets (id, name, public) values ('attachments', 'attachments', false);
create policy "Signed-in users can read attachments"
  on storage.objects for select
  to authenticated
  using (bucket_id = 'attachments');
create policy "Signed-in users can see buckets"
  on storage.buckets for select
  to authenticated
  using (true);
