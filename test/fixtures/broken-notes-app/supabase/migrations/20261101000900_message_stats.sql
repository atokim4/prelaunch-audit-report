-- Message totals for the signed-in user's dashboard.
create function public.get_message_stats()
returns table (sent bigint, received bigint)
language sql
stable
security definer
as $$
  select
    (select count(*) from public.messages where sender_id = auth.uid()),
    (select count(*) from public.messages where recipient_id = auth.uid())
$$;

revoke execute on function public.get_message_stats() from public, anon;
grant execute on function public.get_message_stats() to authenticated;
