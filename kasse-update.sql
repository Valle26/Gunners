-- =====================================================================
--  Kasse-Folie am Kabinen-TV: Bankverbindung für den QR-Code mitliefern
--  Supabase -> SQL Editor -> New query -> alles einfügen -> Run
-- =====================================================================
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
