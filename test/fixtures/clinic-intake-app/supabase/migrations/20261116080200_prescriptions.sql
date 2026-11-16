create table public.prescriptions (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.patients (id) on delete cascade,
  medication text not null,
  dosage text not null,
  created_at timestamptz not null default now()
);

alter table public.prescriptions enable row level security;

create policy "Clinicians read prescriptions of their patients"
  on public.prescriptions for select
  to authenticated
  using (exists (select 1 from public.patients p where p.id = patient_id and p.clinician_id = (select auth.uid())));

create policy "Clinicians write prescriptions for their patients"
  on public.prescriptions for insert
  to authenticated
  with check (exists (select 1 from public.patients p where p.id = patient_id and p.clinician_id = (select auth.uid())));
