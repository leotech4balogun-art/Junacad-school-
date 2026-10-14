-- Junacad: private student support, profile photos, and secure account-action foundation
-- Run in Supabase SQL Editor as project owner. This does not alter existing class chat or fee records.

alter table public.school_profiles
  add column if not exists avatar_path text;

create table if not exists public.school_private_messages (
  id uuid primary key default gen_random_uuid(),
  student_auth_user_id uuid not null references auth.users(id) on delete cascade,
  subject text not null check (char_length(subject) between 1 and 160),
  message text not null check (char_length(message) between 1 and 5000),
  attachment_path text,
  status text not null default 'open' check (status in ('open','in_progress','resolved')),
  admin_reply text,
  admin_reply_by uuid references auth.users(id) on delete set null,
  admin_replied_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists school_private_messages_student_created_idx
  on public.school_private_messages(student_auth_user_id, created_at desc);
create index if not exists school_private_messages_status_created_idx
  on public.school_private_messages(status, created_at desc);

alter table public.school_private_messages enable row level security;

drop policy if exists "Students read own private messages" on public.school_private_messages;
create policy "Students read own private messages"
  on public.school_private_messages for select to authenticated
  using (
    student_auth_user_id = auth.uid()
    or exists (
      select 1 from public.school_profiles p
      where p.auth_user_id = auth.uid() and p.role = 'admin'
    )
  );

drop policy if exists "Students create own private messages" on public.school_private_messages;
create policy "Students create own private messages"
  on public.school_private_messages for insert to authenticated
  with check (
    student_auth_user_id = auth.uid()
    and exists (
      select 1 from public.school_profiles p
      where p.auth_user_id = auth.uid() and p.role = 'student'
    )
  );

drop policy if exists "Admins manage private messages" on public.school_private_messages;
create policy "Admins manage private messages"
  on public.school_private_messages for update to authenticated
  using (
    exists (
      select 1 from public.school_profiles p
      where p.auth_user_id = auth.uid() and p.role = 'admin'
    )
  )
  with check (
    exists (
      select 1 from public.school_profiles p
      where p.auth_user_id = auth.uid() and p.role = 'admin'
    )
  );

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('student-private-attachments', 'student-private-attachments', false, 5242880, array['image/jpeg','image/png','image/webp','application/pdf']),
  ('student-profile-photos', 'student-profile-photos', false, 3145728, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Users upload own private student attachments" on storage.objects;
create policy "Users upload own private student attachments"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'student-private-attachments'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

drop policy if exists "Students and admins read private student attachments" on storage.objects;
create policy "Students and admins read private student attachments"
  on storage.objects for select to authenticated
  using (
    bucket_id = 'student-private-attachments'
    and (
      (storage.foldername(name))[1] = auth.uid()::text
      or exists (
        select 1 from public.school_profiles p
        where p.auth_user_id = auth.uid() and p.role = 'admin'
      )
    )
  );

drop policy if exists "Users upload own profile photos" on storage.objects;
create policy "Users upload own profile photos"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'student-profile-photos'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

drop policy if exists "Users update own profile photos" on storage.objects;
create policy "Users update own profile photos"
  on storage.objects for update to authenticated
  using (
    bucket_id = 'student-profile-photos'
    and (storage.foldername(name))[1] = auth.uid()::text
  )
  with check (
    bucket_id = 'student-profile-photos'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

drop policy if exists "Users and admins read profile photos" on storage.objects;
create policy "Users and admins read profile photos"
  on storage.objects for select to authenticated
  using (
    bucket_id = 'student-profile-photos'
    and (
      (storage.foldername(name))[1] = auth.uid()::text
      or exists (
        select 1 from public.school_profiles p
        where p.auth_user_id = auth.uid() and p.role = 'admin'
      )
    )
  );

drop policy if exists "Users delete own profile photos" on storage.objects;
create policy "Users delete own profile photos"
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'student-profile-photos'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

-- Intentionally no client-side delete policy for support messages or fee records.
-- PIN-verified account/fee editing and deletion must be performed by a server-side function.
