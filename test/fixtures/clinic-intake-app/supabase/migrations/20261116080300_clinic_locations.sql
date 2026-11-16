-- Public list of clinic addresses for the website footer.
create table public.clinic_locations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  address text not null,
  description text
);

alter table public.clinic_locations enable row level security;

create policy "Anyone can read clinic locations"
  on public.clinic_locations for select
  to anon, authenticated
  using (true);
