-- Used by the admin page to upgrade or downgrade a customer.
create function public.admin_set_plan(target_user uuid, new_plan text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.profiles set plan = new_plan where id = target_user;
end;
$$;

grant execute on function public.admin_set_plan(uuid, text) to anon, authenticated;
