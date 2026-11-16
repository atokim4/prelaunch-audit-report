insert into storage.buckets (id, name, public)
values ('lab-results', 'lab-results', true);

create policy "Staff can upload lab results"
  on storage.objects for insert
  to authenticated
  with check (bucket_id = 'lab-results');

-- Logos for the marketing site: meant to be public.
insert into storage.buckets (id, name, public)
values ('clinic-logos', 'clinic-logos', true);
