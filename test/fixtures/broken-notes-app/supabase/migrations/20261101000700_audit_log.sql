-- Written by the API routes on sign-in, plan changes and exports.
create table public.audit_log (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users (id) on delete set null,
  action text not null,
  ip_address inet,
  created_at timestamptz not null default now()
);

create index audit_log_user_id_idx on public.audit_log (user_id);
