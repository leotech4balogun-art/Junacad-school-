-- Junacad High School: support teachers assigned to multiple classes.
-- Run this once in Supabase SQL Editor for project ummipolawycrnxcxsrej.
-- Staff class assignments are stored in school_profiles.class_name as comma-separated class names.

create or replace function public.is_teacher_assigned_to_class(target_class text)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.school_profiles p
    where p.auth_user_id = auth.uid()
      and p.role = 'teacher'
      and target_class = any (
        string_to_array(
          regexp_replace(coalesce(p.class_name, ''), '\s*,\s*', ',', 'g'),
          ','
        )
      )
  );
$$;

revoke all on function public.is_teacher_assigned_to_class(text) from public;
grant execute on function public.is_teacher_assigned_to_class(text) to authenticated;

drop policy if exists "Teachers read homework for assigned classes" on public.school_homework;
create policy "Teachers read homework for assigned classes"
on public.school_homework
for select
to authenticated
using (public.is_teacher_assigned_to_class(class_name));

drop policy if exists "Teachers read messages for assigned classes" on public.school_messages;
create policy "Teachers read messages for assigned classes"
on public.school_messages
for select
to authenticated
using (public.is_teacher_assigned_to_class(class_name));

drop policy if exists "Teachers send messages to assigned classes" on public.school_messages;
create policy "Teachers send messages to assigned classes"
on public.school_messages
for insert
to authenticated
with check (
  sender_id = auth.uid()
  and public.is_teacher_assigned_to_class(class_name)
);
