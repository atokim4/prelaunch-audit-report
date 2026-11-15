create table public.activities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  deal_id uuid references public.deals (id) on delete cascade,
  kind text not null,
  body text,
  created_at timestamptz not null default now()
);

alter table public.activities enable row level security;

create policy "Users can view their activity"
  on public.activities for select
  to authenticated
  using (auth.uid() = user_id);

create policy "Signed-in users can log activity"
  on public.activities for insert
  to authenticated
  with check (auth.uid() is not null);
