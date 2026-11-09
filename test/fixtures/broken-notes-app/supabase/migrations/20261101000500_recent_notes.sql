-- Latest notes for the activity widget.
create view public.recent_notes as
  select id, user_id, title, created_at
  from public.notes
  order by created_at desc
  limit 50;
