-- Lets users find each other by email when starting a conversation.
create view public.user_directory as
  select id, email, created_at
  from auth.users;

grant select on public.user_directory to anon, authenticated;
