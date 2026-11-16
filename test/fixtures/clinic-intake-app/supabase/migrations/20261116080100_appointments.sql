create table public.appointments (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.patients (id) on delete cascade,
  scheduled_at timestamptz not null,
  reason text not null,
  clinical_notes text,
  created_at timestamptz not null default now()
);

alter table public.appointments enable row level security;

create policy "Clinicians see appointments of their patients"
  on public.appointments for select
  to authenticated
  using (exists (select 1 from public.patients p where p.id = patient_id and p.clinician_id = auth.uid()));

create policy "Clinicians book appointments for their patients"
  on public.appointments for insert
  to authenticated
  with check (exists (select 1 from public.patients p where p.id = patient_id and p.clinician_id = auth.uid()));

-- Today's schedule for the front desk screen.
create view public.todays_schedule as
  select a.id, a.scheduled_at, a.reason, p.full_name, p.date_of_birth, p.clinician_id
    from public.appointments a
    join public.patients p on p.id = a.patient_id
   where a.scheduled_at::date = current_date;
