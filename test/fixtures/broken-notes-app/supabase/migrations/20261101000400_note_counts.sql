-- Per-user note count for the dashboard. Runs with the caller's permissions.
create view public.note_counts
with (security_invoker = true)
as
  select user_id, count(*) as note_count
  from public.notes
  group by user_id;
