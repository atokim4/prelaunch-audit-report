-- Flags the client reads at start-up.
create table public.feature_flags (
  key text primary key,
  enabled boolean not null default false
);

alter table public.feature_flags enable row level security;
