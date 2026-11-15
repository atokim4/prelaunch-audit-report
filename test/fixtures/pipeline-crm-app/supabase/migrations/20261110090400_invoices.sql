create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references auth.users (id) on delete cascade,
  number text not null,
  amount_cents integer not null,
  status text not null default 'open',
  created_at timestamptz not null default now()
);

create index invoices_customer_id_idx on public.invoices (customer_id);
