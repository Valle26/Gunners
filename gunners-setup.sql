-- =====================================================================
--  Gunners App – zentrale Rechte für Kabine, Shot Map, Kasse und Instagram
--  Supabase -> SQL Editor -> New query -> alles einfügen -> Run
--  Kann gefahrlos mehrmals ausgeführt werden.
--  Beim ersten Mal werden bestehende Freischaltungen aus Kabine, Shot Map und Kasse übernommen.
--  Enthält auch die Mannschaften (Kampfmannschaft, U15, KM2 …) mit eigener Kabine.
--  Die Daten (Spiele, Strafen, Linien) bleiben unverändert.
-- =====================================================================

-- 1. Eine Zeile pro Person: Status, Admin und Recht pro App
create table if not exists public.g_access (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  email      text,
  name       text,
  status     text not null default 'wait' check (status in ('wait','ok','off')),
  is_admin   boolean not null default false,
  kabine     text check (kabine in ('view','edit','tv')),
  shotmap    text check (shotmap in ('edit')),
  kasse      text check (kasse in ('edit')),
  created_at timestamptz not null default now()
);
-- Rechte für weitere Mannschaften: {"u15":"edit","km2":"view"}. Die Kampfmannschaft steht in der Spalte kabine.
alter table public.g_access add column if not exists teams jsonb not null default '{}'::jsonb;
-- Recht für den Instagram-Bereich
alter table public.g_access add column if not exists instagram text check (instagram in ('edit'));

-- Mannschaften mit eigener Kabine (eigene Spieler, Spiele, Trainings, eigener Fernseher)
create table if not exists public.g_teams (
  id         text primary key check (id ~ '^[a-z0-9-]{1,20}$'),
  name       text not null,
  sort       int  not null default 0,
  created_at timestamptz not null default now()
);
-- Kurzname für die Titel am Fernseher („Gunners vs …“, „Warriors vs …“), auch zum Erkennen in der Shot Map
alter table public.g_teams add column if not exists short text;
insert into public.g_teams (id, name, short, sort) values ('km', 'Kampfmannschaft', 'Gunners', 0) on conflict (id) do nothing;
update public.g_teams set short = 'Gunners' where id = 'km' and short is null;
insert into public.g_teams (id, name, short, sort) values ('km2', 'EC Warriors Zirl', 'Warriors', 1)
  on conflict (id) do update set name = 'EC Warriors Zirl', short = 'Warriors' where public.g_teams.short is null;

-- 2. Hilfsfunktionen
create or replace function public.g_is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.g_access where user_id = auth.uid() and status = 'ok'), false)
$$;
create or replace function public.g_app(app text)
returns text language sql stable security definer set search_path = public as $$
  select case when a.status <> 'ok' then null
              when a.is_admin then 'admin'
              else case app when 'kabine' then a.kabine when 'shotmap' then a.shotmap when 'kasse' then a.kasse when 'instagram' then a.instagram end end
  from public.g_access a where a.user_id = auth.uid()
$$;
-- Die Kabine fragt ihre Rolle über kb_role() ab: jetzt aus den zentralen Rechten
create or replace function public.kb_role()
returns text language sql stable security definer set search_path = public as $$
  select case public.g_app('kabine') when 'admin' then 'admin' when 'edit' then 'trainer' when 'view' then 'view' when 'tv' then 'tv' end
$$;
-- Recht in der Kabine einer Mannschaft: admin, edit, view oder tv (TV-Login gehört immer zu genau dieser Kabine)
create or replace function public.g_kab(t text)
returns text language sql stable security definer set search_path = public as $$
  select case when a.status <> 'ok' then null
              when a.is_admin then 'admin'
              when t = 'km' then a.kabine
              else nullif(a.teams ->> t, '') end
  from public.g_access a where a.user_id = auth.uid()
$$;
-- Irgendein Kabinen-Recht (für Shot Map und Kasse auf dem Fernseher) bzw. irgendein Bearbeiten-Recht (Fotos hochladen)
create or replace function public.g_kab_any(need_edit boolean default false)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select a.status = 'ok' and (a.is_admin or
           (case when need_edit then a.kabine = 'edit' or exists (select 1 from jsonb_each_text(a.teams) e where e.value = 'edit')
                 else a.kabine is not null or exists (select 1 from jsonb_each_text(a.teams) e where e.value in ('view','edit','tv')) end))
         from public.g_access a where a.user_id = auth.uid()), false)
$$;
grant execute on function public.g_kab(text) to authenticated;
grant execute on function public.g_kab_any(boolean) to authenticated;
grant execute on function public.g_is_admin() to authenticated;
grant execute on function public.g_app(text) to authenticated;
grant execute on function public.kb_role() to authenticated;

-- Schutz: den eigenen Admin-Zugang kann man sich nicht selbst wegnehmen
create or replace function public.g_guard()
returns trigger language plpgsql as $$
begin
  if auth.uid() is not null and old.user_id = auth.uid()
     and (new.is_admin is distinct from old.is_admin or new.status is distinct from old.status) then
    raise exception 'Den eigenen Zugang kannst du nicht ändern.';
  end if;
  return new;
end $$;
drop trigger if exists g_access_guard on public.g_access;
create trigger g_access_guard before update on public.g_access for each row execute function public.g_guard();

-- 3. Zugriffsregeln für die Rechte-Tabelle
alter table public.g_access enable row level security;
drop policy if exists g_read on public.g_access;
drop policy if exists g_join on public.g_access;
drop policy if exists g_update on public.g_access;
drop policy if exists g_delete on public.g_access;
create policy g_read on public.g_access for select to authenticated
  using (user_id = auth.uid() or public.g_is_admin());
create policy g_join on public.g_access for insert to authenticated
  with check (user_id = auth.uid() and status = 'wait' and not is_admin and kabine is null and shotmap is null and kasse is null and instagram is null and teams = '{}'::jsonb);
create policy g_update on public.g_access for update to authenticated
  using (public.g_is_admin()) with check (public.g_is_admin());
create policy g_delete on public.g_access for delete to authenticated
  using (public.g_is_admin() and user_id <> auth.uid());

do $$ begin
  alter publication supabase_realtime add table public.g_access;
exception when duplicate_object then null; end $$;

alter table public.g_teams enable row level security;
drop policy if exists g_teams_read on public.g_teams;
drop policy if exists g_teams_write on public.g_teams;
create policy g_teams_read on public.g_teams for select to authenticated
  using (exists (select 1 from public.g_access a where a.user_id = auth.uid() and a.status = 'ok'));
create policy g_teams_write on public.g_teams for all to authenticated
  using (public.g_is_admin()) with check (public.g_is_admin());
do $$ begin
  alter publication supabase_realtime add table public.g_teams;
exception when duplicate_object then null; end $$;

-- 4. Bestehende Freischaltungen übernehmen (nur beim allerersten Ausführen)
do $$ begin
  if exists (select 1 from public.g_access) then return; end if;
  if to_regclass('public.kb_members') is not null then
    insert into public.g_access (user_id, email, name, status, is_admin, kabine, created_at)
    select user_id, email, name, status, role = 'admin',
           case role when 'trainer' then 'edit' when 'view' then 'view' when 'tv' then 'tv' end, created_at
    from public.kb_members
    on conflict (user_id) do update set
      is_admin = public.g_access.is_admin or excluded.is_admin,
      kabine   = coalesce(public.g_access.kabine, excluded.kabine),
      name     = coalesce(public.g_access.name, excluded.name),
      status   = case when public.g_access.status = 'ok' or excluded.status = 'ok' then 'ok' else public.g_access.status end;
  end if;
  if to_regclass('public.sm_members') is not null then
    insert into public.g_access (user_id, email, status, shotmap, created_at)
    select user_id, email, case when approved then 'ok' else 'wait' end, case when approved then 'edit' end, coalesce(created_at, now())
    from public.sm_members
    on conflict (user_id) do update set
      shotmap = coalesce(public.g_access.shotmap, excluded.shotmap),
      email   = coalesce(public.g_access.email, excluded.email),
      status  = case when public.g_access.status = 'ok' or excluded.status = 'ok' then 'ok' else public.g_access.status end;
  end if;
  if to_regclass('public.members') is not null then
    insert into public.g_access (user_id, email, status, kasse, created_at)
    select user_id, email, case when approved then 'ok' else 'wait' end, case when approved then 'edit' end, coalesce(created_at, now())
    from public.members where user_id is not null
    on conflict (user_id) do update set
      kasse  = coalesce(public.g_access.kasse, excluded.kasse),
      email  = coalesce(public.g_access.email, excluded.email),
      status = case when public.g_access.status = 'ok' or excluded.status = 'ok' then 'ok' else public.g_access.status end;
  end if;
end $$;

-- 5. Kabine: jede Mannschaft hat ihre eigenen Einträge (Spalte team)
do $$ declare r record; begin
  if to_regclass('public.kb_docs') is not null then
    execute 'alter table public.kb_docs add column if not exists team text not null default ''km''';
    execute 'create index if not exists kb_docs_team on public.kb_docs (team)';
    for r in select policyname from pg_policies where schemaname = 'public' and tablename = 'kb_docs' loop
      execute format('drop policy %I on public.kb_docs', r.policyname);
    end loop;
    execute $p$create policy kb_docs_read on public.kb_docs for select to authenticated
             using (public.g_kab(team) is not null)$p$;
    execute $p$create policy kb_docs_insert on public.kb_docs for insert to authenticated
             with check (public.g_kab(team) in ('admin','edit')
                         and ((team = 'km' and position('/' in key) = 0) or key like team || '/%'))$p$;
    execute $p$create policy kb_docs_update on public.kb_docs for update to authenticated
             using (public.g_kab(team) in ('admin','edit'))
             with check (public.g_kab(team) in ('admin','edit')
                         and ((team = 'km' and position('/' in key) = 0) or key like team || '/%'))$p$;
    execute $p$create policy kb_docs_delete on public.kb_docs for delete to authenticated
             using (public.g_kab(team) in ('admin','edit'))$p$;
  end if;
end $$;
-- Fotos: hochladen darf, wer in irgendeiner Mannschaft bearbeiten darf
do $$ begin
  if exists (select 1 from storage.buckets where id = 'kabine') then
    drop policy if exists kb_files_insert on storage.objects;
    drop policy if exists kb_files_update on storage.objects;
    drop policy if exists kb_files_delete on storage.objects;
    create policy kb_files_insert on storage.objects for insert to authenticated
      with check (bucket_id = 'kabine' and public.g_kab_any(true));
    create policy kb_files_update on storage.objects for update to authenticated
      using (bucket_id = 'kabine' and public.g_kab_any(true));
    create policy kb_files_delete on storage.objects for delete to authenticated
      using (bucket_id = 'kabine' and public.g_kab_any(true));
  end if;
end $$;

-- 6. Shot Map: Zugriff nach zentralen Rechten, Kabine (inkl. TV) darf lesen
do $$ declare r record; begin
  if to_regclass('public.sm_games') is not null then
    for r in select policyname from pg_policies where schemaname = 'public' and tablename = 'sm_games' loop
      execute format('drop policy %I on public.sm_games', r.policyname);
    end loop;
    execute 'alter table public.sm_games enable row level security';
    execute $p$create policy g_sm_rw on public.sm_games for all to authenticated
             using (public.g_app('shotmap') is not null) with check (public.g_app('shotmap') is not null)$p$;
    execute $p$create policy kb_sm_read on public.sm_games for select to authenticated
             using (public.g_kab_any())$p$;
  end if;
end $$;

-- 7. Kasse: Zugriff nach zentralen Rechten
do $$ declare r record; begin
  if to_regclass('public.kasse_state') is not null then
    for r in select policyname from pg_policies where schemaname = 'public' and tablename = 'kasse_state' loop
      execute format('drop policy %I on public.kasse_state', r.policyname);
    end loop;
    execute 'alter table public.kasse_state enable row level security';
    execute $p$create policy g_kasse_rw on public.kasse_state for all to authenticated
             using (public.g_app('kasse') is not null) with check (public.g_app('kasse') is not null)$p$;
  end if;
end $$;

-- 8. Kasse für die Kabinen-Folie: nur Namen und Beträge, keine Strafentexte
create or replace function public.kb_kasse()
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare st jsonb;
begin
  if not public.g_kab_any() or to_regclass('public.kasse_state') is null then return null; end if;
  execute 'select state::jsonb from public.kasse_state where id = ''shared''' into st;
  if st is null then return null; end if;
  return jsonb_build_object(
    'players', coalesce((select jsonb_agg(jsonb_build_object('id', p->'id', 'name', p->'name', 'createdMonth', p->'createdMonth'))
                         from jsonb_array_elements(coalesce(st->'players','[]'::jsonb)) p), '[]'::jsonb),
    'entries', coalesce((select jsonb_agg(jsonb_build_object('playerId', e->'playerId', 'type', e->'type', 'amount', e->'amount',
                                 'paid', e->'paid', 'paidInterest', e->'paidInterest', 'ts', e->'ts', 'catalogId', e->'catalogId', 'monthKey', e->'monthKey'))
                         from jsonb_array_elements(coalesce(st->'entries','[]'::jsonb)) e), '[]'::jsonb),
    'catalog', coalesce((select jsonb_agg(jsonb_build_object('id', c->'id', 'type', c->'type', 'amount', c->'amount',
                                 'recurring', c->'recurring', 'startMonth', c->'startMonth'))
                         from jsonb_array_elements(coalesce(st->'catalog','[]'::jsonb)) c where c->>'type' = 'beitrag'), '[]'::jsonb),
    'interest', st->'interest',
    'bank', st->'bank');
end $$;
revoke all on function public.kb_kasse() from public, anon;
grant execute on function public.kb_kasse() to authenticated;

-- 9. Instagram: Spiele, Einträge pro Spiel, Logos, Fotos pro Reiter pro Spiel (Torschützen, Spieler des Spiels …) und Gegner-Logos
create table if not exists public.ig_docs (
  key        text primary key check (key ~ '^(game|note|logo):[A-Za-z0-9_.-]{1,120}$'),
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);
-- Fotos pro Reiter (gameday, period, final, goal, mvp, lineup, sched) und Gegner-Logos (logos)
create table if not exists public.ig_photos (
  id         uuid primary key default gen_random_uuid(),
  tab        text not null check (tab in ('gameday','period','final','goal','mvp','lineup','sched')),
  url        text not null,
  path       text,
  w          int,
  h          int,
  created_at timestamptz not null default now(),
  created_by uuid default auth.uid()
);
create unique index if not exists ig_photos_tab_url on public.ig_photos (tab, url);
-- Fotos und Logos: Reiter „logos“ und Name (für Logos)
alter table public.ig_photos add column if not exists name text;
alter table public.ig_photos drop constraint if exists ig_photos_tab_check;
alter table public.ig_photos add constraint ig_photos_tab_check check (tab in ('gameday','period','final','goal','mvp','lineup','sched','logos'));


alter table public.ig_docs enable row level security;
alter table public.ig_photos enable row level security;
drop policy if exists ig_docs_rw on public.ig_docs;
drop policy if exists ig_photos_rw on public.ig_photos;
create policy ig_docs_rw on public.ig_docs for all to authenticated
  using (public.g_app('instagram') is not null) with check (public.g_app('instagram') is not null);
create policy ig_photos_rw on public.ig_photos for all to authenticated
  using (public.g_app('instagram') is not null) with check (public.g_app('instagram') is not null);
do $$ begin alter publication supabase_realtime add table public.ig_docs; exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.ig_photos; exception when duplicate_object then null; end $$;

-- 3. Speicher für Fotos und Logos (öffentlich lesbar wie die Kabinen-Fotos)
insert into storage.buckets (id, name, public) values ('instagram', 'instagram', true) on conflict (id) do nothing;
drop policy if exists ig_files_read on storage.objects;
drop policy if exists ig_files_insert on storage.objects;
drop policy if exists ig_files_update on storage.objects;
drop policy if exists ig_files_delete on storage.objects;
create policy ig_files_read on storage.objects for select to authenticated
  using (bucket_id = 'instagram');
create policy ig_files_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'instagram' and public.g_app('instagram') is not null);
create policy ig_files_update on storage.objects for update to authenticated
  using (bucket_id = 'instagram' and public.g_app('instagram') is not null);
create policy ig_files_delete on storage.objects for delete to authenticated
  using (bucket_id = 'instagram' and public.g_app('instagram') is not null);

-- 4. Instagram liest Spieler und Spiele der Kampfmannschaft und die Shot Map
do $$ begin
  if to_regclass('public.kb_docs') is not null then
    execute 'drop policy if exists kb_docs_ig_read on public.kb_docs';
    execute $p$create policy kb_docs_ig_read on public.kb_docs for select to authenticated
             using (team = 'km' and public.g_app('instagram') is not null)$p$;
    begin execute 'alter publication supabase_realtime add table public.kb_docs'; exception when duplicate_object then null; end;
  end if;
  if to_regclass('public.sm_games') is not null then
    execute 'drop policy if exists ig_sm_read on public.sm_games';
    execute $p$create policy ig_sm_read on public.sm_games for select to authenticated
             using (public.g_app('instagram') is not null)$p$;
    begin execute 'alter publication supabase_realtime add table public.sm_games'; exception when duplicate_object then null; end;
  end if;
end $$;

-- 10. Kontrolle: alle Personen mit ihren Rechten
select coalesce(name, email) as person, status, is_admin as admin, kabine, teams as weitere_mannschaften, shotmap, kasse, instagram
from public.g_access order by is_admin desc, status, created_at;
