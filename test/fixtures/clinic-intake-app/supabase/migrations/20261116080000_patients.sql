create table public.patients (
  id uuid primary key default gen_random_uuid(),
  clinician_id uuid not null references auth.users (id) on delete cascade,
  full_name text not null,
  date_of_birth date,
  mrn text,
  diagnosis text,
  insurance_member_id text,
  phone text,
  created_at timestamptz not null default now()
);

alter table public.patients enable row level security;

create policy "Clinic staff can view patients"
  on public.patients for select
  to authenticated
  using (auth.role() = 'authenticated');

create policy "Clinicians add their patients"
  on public.patients for insert
  to authenticated
  with check (auth.uid() = clinician_id);

create policy "Clinicians update their patients"
  on public.patients for update
  to authenticated
  using (auth.uid() = clinician_id)
  with check (auth.uid() = clinician_id);
