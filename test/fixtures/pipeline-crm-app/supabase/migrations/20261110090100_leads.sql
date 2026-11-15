create table public.leads (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  name text not null,
  email text,
  phone text,
  created_at timestamptz not null default now()
);

alter table public.leads enable row level security;

create policy "Enable read access for all users"
  on public.leads for select
  using (true);

create policy "Users can add leads"
  on public.leads for insert
  to authenticated
  with check (auth.uid() = owner_id);

create policy "Users can edit their leads"
  on public.leads for update
  to authenticated
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

create function public.delete_lead(lead_id uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  delete from public.leads where id = lead_id;
$$;
