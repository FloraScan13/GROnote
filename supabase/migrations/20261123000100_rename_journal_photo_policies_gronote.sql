-- Rename the existing journal-photo storage policies from the former app name to GROnote.
-- Policy conditions are unchanged; this preserves per-user storage isolation.

drop policy if exists "Users can view own FloraScan journal photos" on storage.objects;
drop policy if exists "Users can upload own FloraScan journal photos" on storage.objects;
drop policy if exists "Users can update own FloraScan journal photos" on storage.objects;
drop policy if exists "Users can delete own FloraScan journal photos" on storage.objects;

drop policy if exists "Users can view own GROnote journal photos" on storage.objects;
create policy "Users can view own GROnote journal photos"
on storage.objects for select to authenticated
using (
  bucket_id = 'journal-photos'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

create policy "Users can upload own GROnote journal photos"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'journal-photos'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

create policy "Users can update own GROnote journal photos"
on storage.objects for update to authenticated
using (
  bucket_id = 'journal-photos'
  and (storage.foldername(name))[1] = (select auth.uid())::text
)
with check (
  bucket_id = 'journal-photos'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

create policy "Users can delete own GROnote journal photos"
on storage.objects for delete to authenticated
using (
  bucket_id = 'journal-photos'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);
