-- Direct messages between two users.
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  recipient_id uuid not null references auth.users (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);

create index messages_sender_id_idx on public.messages (sender_id);
create index messages_recipient_id_idx on public.messages (recipient_id);

alter table public.messages enable row level security;

create policy "Enable read access for all users"
  on public.messages for select
  using (true);

create policy "Users can send messages"
  on public.messages for insert
  to authenticated
  with check ((select auth.uid()) = sender_id);
