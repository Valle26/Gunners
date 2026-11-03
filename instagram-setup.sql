-- =====================================================================
--  Gunners App – Instagram
--  Supabase -> SQL Editor -> New query -> alles einfügen -> Run
--  Kann gefahrlos mehrmals ausgeführt werden.
--  Legt an: Recht „Instagram“, Tabellen ig_docs und ig_photos, Speicher „instagram“,
--  Lesezugriff auf Spieler/Spiele der Kampfmannschaft und auf die Shot Map,
--  und übernimmt die 9 Fotos aus der Testseite in alle Reiter.
-- =====================================================================

-- 1. Recht „Instagram“ pro Person
alter table public.g_access add column if not exists instagram text check (instagram in ('edit'));

create or replace function public.g_app(app text)
returns text language sql stable security definer set search_path = public as $$
  select case when a.status <> 'ok' then null
              when a.is_admin then 'admin'
              else case app when 'kabine' then a.kabine when 'shotmap' then a.shotmap when 'kasse' then a.kasse when 'instagram' then a.instagram end end
  from public.g_access a where a.user_id = auth.uid()
$$;
grant execute on function public.g_app(text) to authenticated;

-- Neue Registrierungen dürfen sich kein Recht selbst geben
drop policy if exists g_join on public.g_access;
create policy g_join on public.g_access for insert to authenticated
  with check (user_id = auth.uid() and status = 'wait' and not is_admin and kabine is null and shotmap is null and kasse is null and instagram is null and teams = '{}'::jsonb);

-- 2. Spiele, Einträge pro Spiel (Torschützen, Spieler des Spiels …) und Gegner-Logos
create table if not exists public.ig_docs (
  key        text primary key check (key ~ '^(game|note|logo):[A-Za-z0-9_.-]{1,120}$'),
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);
-- Fotos pro Reiter (gameday, period, final, goal, mvp, lineup, sched)
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

-- 5. Die 9 Fotos aus der Testseite in alle Reiter übernehmen (Dateien liegen im Ordner instagram/import)
insert into public.ig_photos (tab, url, w, h, created_at) values
  ('gameday', 'import/01.jpg', 2048, 1363, to_timestamp(1793737407421/1000.0)),
  ('gameday', 'import/02.jpg', 2048, 1363, to_timestamp(1793738331379/1000.0)),
  ('gameday', 'import/03.jpg', 2048, 1363, to_timestamp(1793738377573/1000.0)),
  ('gameday', 'import/04.jpg', 2048, 1363, to_timestamp(1793738424359/1000.0)),
  ('gameday', 'import/05.jpg', 2048, 1363, to_timestamp(1793738491126/1000.0)),
  ('gameday', 'import/06.jpg', 2048, 1363, to_timestamp(1793738492363/1000.0)),
  ('gameday', 'import/07.jpg', 2048, 1363, to_timestamp(1793738527442/1000.0)),
  ('gameday', 'import/08.jpg', 2048, 1363, to_timestamp(1793738578782/1000.0)),
  ('gameday', 'import/09.jpg', 2048, 1363, to_timestamp(1793738579835/1000.0)),
  ('period', 'import/01.jpg', 2048, 1363, to_timestamp(1793737407421/1000.0)),
  ('period', 'import/02.jpg', 2048, 1363, to_timestamp(1793738331379/1000.0)),
  ('period', 'import/03.jpg', 2048, 1363, to_timestamp(1793738377573/1000.0)),
  ('period', 'import/04.jpg', 2048, 1363, to_timestamp(1793738424359/1000.0)),
  ('period', 'import/05.jpg', 2048, 1363, to_timestamp(1793738491126/1000.0)),
  ('period', 'import/06.jpg', 2048, 1363, to_timestamp(1793738492363/1000.0)),
  ('period', 'import/07.jpg', 2048, 1363, to_timestamp(1793738527442/1000.0)),
  ('period', 'import/08.jpg', 2048, 1363, to_timestamp(1793738578782/1000.0)),
  ('period', 'import/09.jpg', 2048, 1363, to_timestamp(1793738579835/1000.0)),
  ('final', 'import/01.jpg', 2048, 1363, to_timestamp(1793737407421/1000.0)),
  ('final', 'import/02.jpg', 2048, 1363, to_timestamp(1793738331379/1000.0)),
  ('final', 'import/03.jpg', 2048, 1363, to_timestamp(1793738377573/1000.0)),
  ('final', 'import/04.jpg', 2048, 1363, to_timestamp(1793738424359/1000.0)),
  ('final', 'import/05.jpg', 2048, 1363, to_timestamp(1793738491126/1000.0)),
  ('final', 'import/06.jpg', 2048, 1363, to_timestamp(1793738492363/1000.0)),
  ('final', 'import/07.jpg', 2048, 1363, to_timestamp(1793738527442/1000.0)),
  ('final', 'import/08.jpg', 2048, 1363, to_timestamp(1793738578782/1000.0)),
  ('final', 'import/09.jpg', 2048, 1363, to_timestamp(1793738579835/1000.0)),
  ('goal', 'import/01.jpg', 2048, 1363, to_timestamp(1793737407421/1000.0)),
  ('goal', 'import/02.jpg', 2048, 1363, to_timestamp(1793738331379/1000.0)),
  ('goal', 'import/03.jpg', 2048, 1363, to_timestamp(1793738377573/1000.0)),
  ('goal', 'import/04.jpg', 2048, 1363, to_timestamp(1793738424359/1000.0)),
  ('goal', 'import/05.jpg', 2048, 1363, to_timestamp(1793738491126/1000.0)),
  ('goal', 'import/06.jpg', 2048, 1363, to_timestamp(1793738492363/1000.0)),
  ('goal', 'import/07.jpg', 2048, 1363, to_timestamp(1793738527442/1000.0)),
  ('goal', 'import/08.jpg', 2048, 1363, to_timestamp(1793738578782/1000.0)),
  ('goal', 'import/09.jpg', 2048, 1363, to_timestamp(1793738579835/1000.0)),
  ('mvp', 'import/01.jpg', 2048, 1363, to_timestamp(1793737407421/1000.0)),
  ('mvp', 'import/02.jpg', 2048, 1363, to_timestamp(1793738331379/1000.0)),
  ('mvp', 'import/03.jpg', 2048, 1363, to_timestamp(1793738377573/1000.0)),
  ('mvp', 'import/04.jpg', 2048, 1363, to_timestamp(1793738424359/1000.0)),
  ('mvp', 'import/05.jpg', 2048, 1363, to_timestamp(1793738491126/1000.0)),
  ('mvp', 'import/06.jpg', 2048, 1363, to_timestamp(1793738492363/1000.0)),
  ('mvp', 'import/07.jpg', 2048, 1363, to_timestamp(1793738527442/1000.0)),
  ('mvp', 'import/08.jpg', 2048, 1363, to_timestamp(1793738578782/1000.0)),
  ('mvp', 'import/09.jpg', 2048, 1363, to_timestamp(1793738579835/1000.0)),
  ('lineup', 'import/01.jpg', 2048, 1363, to_timestamp(1793737407421/1000.0)),
  ('lineup', 'import/02.jpg', 2048, 1363, to_timestamp(1793738331379/1000.0)),
  ('lineup', 'import/03.jpg', 2048, 1363, to_timestamp(1793738377573/1000.0)),
  ('lineup', 'import/04.jpg', 2048, 1363, to_timestamp(1793738424359/1000.0)),
  ('lineup', 'import/05.jpg', 2048, 1363, to_timestamp(1793738491126/1000.0)),
  ('lineup', 'import/06.jpg', 2048, 1363, to_timestamp(1793738492363/1000.0)),
  ('lineup', 'import/07.jpg', 2048, 1363, to_timestamp(1793738527442/1000.0)),
  ('lineup', 'import/08.jpg', 2048, 1363, to_timestamp(1793738578782/1000.0)),
  ('lineup', 'import/09.jpg', 2048, 1363, to_timestamp(1793738579835/1000.0)),
  ('sched', 'import/01.jpg', 2048, 1363, to_timestamp(1793737407421/1000.0)),
  ('sched', 'import/02.jpg', 2048, 1363, to_timestamp(1793738331379/1000.0)),
  ('sched', 'import/03.jpg', 2048, 1363, to_timestamp(1793738377573/1000.0)),
  ('sched', 'import/04.jpg', 2048, 1363, to_timestamp(1793738424359/1000.0)),
  ('sched', 'import/05.jpg', 2048, 1363, to_timestamp(1793738491126/1000.0)),
  ('sched', 'import/06.jpg', 2048, 1363, to_timestamp(1793738492363/1000.0)),
  ('sched', 'import/07.jpg', 2048, 1363, to_timestamp(1793738527442/1000.0)),
  ('sched', 'import/08.jpg', 2048, 1363, to_timestamp(1793738578782/1000.0)),
  ('sched', 'import/09.jpg', 2048, 1363, to_timestamp(1793738579835/1000.0))
on conflict (tab, url) do nothing;

-- 6. Spiel gegen den HC Kufstein am 8.11. (aus der Testseite) und das Dragons-Logo
insert into public.ig_docs (key, data) values
  ('game:kufstein-2026-11-08', '{"opp":"HC Kufstein","date":"2026-11-08","time":"19:30","home":true,"venue":"Eishalle Zirl"}'::jsonb),
  ('logo:hc-kufstein', '{"opp":"HC Kufstein","url":"import/logos/hc-kufstein.png"}'::jsonb)
on conflict (key) do nothing;

-- 7. Kontrolle
select coalesce(name, email) as person, is_admin as admin, instagram from public.g_access where status = 'ok' order by is_admin desc, created_at;
