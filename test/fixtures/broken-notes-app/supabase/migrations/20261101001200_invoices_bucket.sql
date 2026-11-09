-- PDF invoices, linked from the billing page.
insert into storage.buckets (id, name, public)
values ('invoices', 'invoices', true);

create policy "Anyone can list invoices"
  on storage.objects for select
  using (bucket_id = 'invoices');
