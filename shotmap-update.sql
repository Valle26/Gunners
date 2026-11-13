-- =====================================================================
--  Gunners App – Shot Map: Spiele und Torhüter aus der Kabine übernehmen
--  Supabase -> SQL Editor -> New query -> alles einfügen -> Run
--  Kann gefahrlos mehrmals ausgeführt werden.
--  Wer die Shot Map erfassen darf, kann Spiele und Spieler der Kampfmannschaft lesen (nicht ändern).
-- =====================================================================
do $$ begin
  if to_regclass('public.kb_docs') is not null then
    execute 'drop policy if exists kb_docs_sm_read on public.kb_docs';
    execute $p$create policy kb_docs_sm_read on public.kb_docs for select to authenticated
             using (team = 'km' and public.g_app('shotmap') is not null)$p$;
  end if;
end $$;
