-- ===========================================================================
-- סכמת מסד הנתונים של האפליקציה (Supabase / Postgres)
-- איך מריצים: ב-Supabase נכנסים ל-SQL Editor, מדביקים את כל הקובץ ולוחצים Run.
-- אפשר להריץ שוב בלי נזק (הקובץ בנוי כך שיתעדכן ולא ייכשל).
-- ===========================================================================

-- 1. טבלת הפרופילים: שורה אחת לכל מי שנרשם (מתאמן או מאמן)
create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  role       text not null default 'trainee' check (role in ('trainee', 'coach')),
  name       text not null default '',
  age        int  check (age between 3 and 120),
  gender     text not null default 'n' check (gender in ('m', 'f', 'n')),
  phone      text,
  email      text,
  created_at timestamptz not null default now()
);
create index if not exists profiles_created_idx on public.profiles (created_at desc);

-- 2. אבטחה ברמת שורה (חובה): בלי זה כל מי שמחזיק את המפתח הציבורי היה רואה הכול
alter table public.profiles enable row level security;

-- פונקציית עזר: האם המשתמש המחובר הוא מאמן?
create or replace function public.is_coach()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'coach');
$$;
revoke all on function public.is_coach() from public;
grant execute on function public.is_coach() to authenticated;

-- 3. מדיניות גישה
drop policy if exists profiles_select_own   on public.profiles;
drop policy if exists profiles_select_coach on public.profiles;
drop policy if exists profiles_insert_own   on public.profiles;
drop policy if exists profiles_update_own   on public.profiles;

-- כל משתמש רואה את הפרופיל שלו
create policy profiles_select_own on public.profiles
  for select to authenticated using (id = auth.uid());
-- מאמן רואה את כולם
create policy profiles_select_coach on public.profiles
  for select to authenticated using (public.is_coach());
-- משתמש יכול ליצור ולעדכן רק את השורה של עצמו
create policy profiles_insert_own on public.profiles
  for insert to authenticated with check (id = auth.uid());
create policy profiles_update_own on public.profiles
  for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- 4. הרשאות ברמת עמודה: אף אחד לא יכול לקבוע לעצמו role דרך האפליקציה
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant insert (id, name, age, gender, phone) on public.profiles to authenticated;
grant update (name, age, gender, phone)      on public.profiles to authenticated;

-- 5. יצירת פרופיל אוטומטית ברגע שמישהו נרשם (גם כשנדרש אישור מייל)
create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer
set search_path = public
as $$
declare
  m jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
begin
  insert into public.profiles (id, email, name, age, gender, phone)
  values (
    new.id,
    new.email,
    left(coalesce(nullif(btrim(m ->> 'name'), ''), 'ללא שם'), 60),
    case when (m ->> 'age') ~ '^\d{1,3}$' and (m ->> 'age')::int between 3 and 120 then (m ->> 'age')::int end,
    case when m ->> 'gender' in ('m', 'f', 'n') then m ->> 'gender' else 'n' end,
    nullif(left(btrim(coalesce(m ->> 'phone', '')), 20), '')
  )
  on conflict (id) do nothing;
  return new;
exception when others then
  return new;  -- לעולם לא לחסום הרשמה בגלל תקלה בפרופיל
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 6. הפיכת החשבון שלכם למאמן.
-- קודם נרשמים באפליקציה עם המייל שלכם, ואז מריצים (בלי הסימון // ועם המייל שלכם):
--   update public.profiles set role = 'coach' where email = 'YOUR@EMAIL.COM';
