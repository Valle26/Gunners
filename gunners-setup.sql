-- =====================================================================
--  Gunners App – zentrale Rechte für Kabine, Shot Map und Kasse
--  Supabase -> SQL Editor -> New query -> alles einfügen -> Run
--  Kann gefahrlos mehrmals ausgeführt werden.
--  Bestehende Freischaltungen aus Kabine, Shot Map und Kasse werden übernommen.
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

-- 2. Hilfsfunktionen
create or replace function public.g_is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.g_access where user_id = auth.uid() and status = 'ok'), false)
$$;
create or replace function public.g_app(app text)
returns text language sql stable security definer set search_path = public as $$
  select case when a.status <> 'ok' then null
              when a.is_admin then 'admin'
              else case app when 'kabine' then a.kabine when 'shotmap' then a.shotmap when 'kasse' then a.kasse end end
  from public.g_access a where a.user_id = auth.uid()
$$;
-- Die Kabine fragt ihre Rolle über kb_role() ab: jetzt aus den zentralen Rechten
create or replace function public.kb_role()
returns text language sql stable security definer set search_path = public as $$
  select case public.g_app('kabine') when 'admin' then 'admin' when 'edit' then 'trainer' when 'view' then 'view' when 'tv' then 'tv' end
$$;
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
  with check (user_id = auth.uid() and status = 'wait' and not is_admin and kabine is null and shotmap is null and kasse is null);
create policy g_update on public.g_access for update to authenticated
  using (public.g_is_admin()) with check (public.g_is_admin());
create policy g_delete on public.g_access for delete to authenticated
  using (public.g_is_admin() and user_id <> auth.uid());

do $$ begin
  alter publication supabase_realtime add table public.g_access;
exception when duplicate_object then null; end $$;

-- 4. Bestehende Freischaltungen übernehmen
do $$ begin
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

-- 5. Shot Map: Zugriff nach zentralen Rechten, Kabine (inkl. TV) darf lesen
do $$ declare r record; begin
  if to_regclass('public.sm_games') is not null then
    for r in select policyname from pg_policies where schemaname = 'public' and tablename = 'sm_games' loop
      execute format('drop policy %I on public.sm_games', r.policyname);
    end loop;
    execute 'alter table public.sm_games enable row level security';
    execute $p$create policy g_sm_rw on public.sm_games for all to authenticated
             using (public.g_app('shotmap') is not null) with check (public.g_app('shotmap') is not null)$p$;
    execute $p$create policy kb_sm_read on public.sm_games for select to authenticated
             using (public.kb_role() in ('admin','trainer','view','tv'))$p$;
  end if;
end $$;

-- 6. Kasse: Zugriff nach zentralen Rechten
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

-- 7. Kasse für die Kabinen-Folie: nur Namen und Beträge, keine Strafentexte
create or replace function public.kb_kasse()
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare st jsonb;
begin
  if public.kb_role() is null or to_regclass('public.kasse_state') is null then return null; end if;
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
    'interest', st->'interest');
end $$;
revoke all on function public.kb_kasse() from public, anon;
grant execute on function public.kb_kasse() to authenticated;

-- 8. Kontrolle: alle übernommenen Personen mit ihren Rechten
select coalesce(name, email) as person, status, is_admin as admin, kabine, shotmap, kasse
from public.g_access order by is_admin desc, status, created_at;
