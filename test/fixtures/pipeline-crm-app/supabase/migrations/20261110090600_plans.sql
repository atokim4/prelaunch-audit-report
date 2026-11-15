-- The public price list on the landing page. Readable by everyone on purpose.
create table public.plans (
  id text primary key,
  name text not null,
  price_cents integer not null
);

alter table public.plans enable row level security;

create policy "Plans are public"
  on public.plans for select
  to anon, authenticated
  using (true);

insert into public.plans (id, name, price_cents) values
  ('free', 'Free', 0),
  ('pro', 'Pro', 1900);
