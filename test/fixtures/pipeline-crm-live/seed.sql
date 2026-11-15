-- Sample data for the live-probe stand-in: two test users, the way a client would create them for the
-- probe, and a few made-up rows each. Nothing here is real data.
insert into auth.users (id, email, raw_user_meta_data) values
  ('00000000-0000-4000-8000-0000000000a1', 'user-a@example.invalid', '{"full_name":"Test User A"}'),
  ('00000000-0000-4000-8000-0000000000b2', 'user-b@example.invalid', '{"full_name":"Test User B"}');

insert into public.leads (owner_id, name, email) values
  ('00000000-0000-4000-8000-0000000000a1', 'Sample lead 1', 'lead1@example.invalid'),
  ('00000000-0000-4000-8000-0000000000a1', 'Sample lead 2', null),
  ('00000000-0000-4000-8000-0000000000b2', 'Sample lead 3', null);

insert into public.deals (owner_id, title, amount_cents, stage) values
  ('00000000-0000-4000-8000-0000000000a1', 'Sample deal A', 120000, 'won'),
  ('00000000-0000-4000-8000-0000000000b2', 'Sample deal B', 50000, 'new');

insert into public.activities (user_id, kind, body) values
  ('00000000-0000-4000-8000-0000000000a1', 'call', 'Sample note'),
  ('00000000-0000-4000-8000-0000000000b2', 'email', 'Sample note');

insert into public.invoices (customer_id, number, amount_cents) values
  ('00000000-0000-4000-8000-0000000000a1', 'INV-0001', 1900),
  ('00000000-0000-4000-8000-0000000000b2', 'INV-0002', 1900);

insert into public.tasks (owner_id, title) values
  ('00000000-0000-4000-8000-0000000000a1', 'Sample task 1'),
  ('00000000-0000-4000-8000-0000000000a1', 'Sample task 2'),
  ('00000000-0000-4000-8000-0000000000b2', 'Sample task 3');

insert into public.notes (user_id, lead_id, body)
  select owner_id, id, 'Sample note body' from public.leads where name = 'Sample lead 1';

insert into storage.objects (bucket_id, name, owner) values
  ('attachments', '00000000-0000-4000-8000-0000000000a1/sample-contract.pdf', '00000000-0000-4000-8000-0000000000a1'),
  ('attachments', '00000000-0000-4000-8000-0000000000b2/sample-quote.pdf', '00000000-0000-4000-8000-0000000000b2');
