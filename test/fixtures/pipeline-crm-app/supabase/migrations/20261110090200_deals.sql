create table public.deals (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  lead_id uuid references public.leads (id) on delete set null,
  title text not null,
  amount_cents integer not null default 0,
  stage text not null default 'new',
  created_at timestamptz not null default now()
);

alter table public.deals enable row level security;

create policy "Authenticated users can view deals"
  on public.deals for select
  using (auth.role() = 'authenticated');

create policy "Users can manage their deals"
  on public.deals for all
  to authenticated
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

create view public.pipeline_summary as
  select owner_id, stage, count(*) as deals, sum(amount_cents) as total_cents
  from public.deals
  group by owner_id, stage;
