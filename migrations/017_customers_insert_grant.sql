-- 017: grant INSERT on customers to the runtime role (2026-09-15 incident).
--
-- Background: 014_app_role_grants.sql laid the DML grants for the dedicated
-- runtime role but omitted INSERT on public.customers. The first production
-- write against customers through the runtime role — the anonymous customer
-- created by the staff "Neue Karte anlegen" flow (PR #24) — failed with
-- "permission denied for table customers" and surfaced as a generic 500
-- (POST /staff/{tenantId}/cards, hotfixed live on 2026-09-15 by the lead).
-- The production grant matrix derived from src/rls-verify.ts REQUIRED_GRANTS
-- shipped the same omission, so `rls-verify` passed while the write path was
-- broken. This migration closes the gap for every fresh environment.
--
-- The grant is conditional on the role existing, matching the convention of
-- migrations 008/009/010/014/016: the dedicated runtime role is provisioned
-- out-of-band, and an unconditional GRANT to an absent role would break the
-- migration run. In any properly provisioned environment (role created before
-- `bun run db:migrate`) this is a no-op guard and the grant is applied.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'stempelpass_runtime') then
    execute 'grant insert on public.customers to stempelpass_runtime';
  end if;
end
$$;