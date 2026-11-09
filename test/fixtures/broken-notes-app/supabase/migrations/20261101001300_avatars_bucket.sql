-- Profile pictures. Private bucket, one folder per user (avatars/<user id>/...).
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', false);

create policy "Users can read their own avatar"
  on storage.objects for select
  to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "Users can upload their own avatar"
  on storage.objects for insert
  to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
