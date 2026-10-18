-- Public (auth-free) display data for the Google-Wallet stamp raster image
-- (GET /wallet/grid/:cardUuid.png, Owner-Entscheid 2026-10-18).
--
-- Why a SECURITY DEFINER resolver (same minimal-privilege pattern as 008/010/
-- 016/020): Google's image fetch carries NO session, and the tenant-isolation
-- RLS policies on `cards`/`stamp_rules`/`tenant_branding` gate every direct
-- read on app.tenant_id — an unauthenticated caller cannot set that context,
-- so a direct table read would hide every row. This function is the single
-- escape hatch: it accepts ONLY a card UUID and returns ONLY aggregate display
-- values (stamp counts, rule threshold, branding colors, reward-ready flag,
-- card revision for the cache-busting `?ts=` URL). It never returns
-- customer/tenant/token/card-code/audit data — no PII.
--
-- Hardening properties (pinned by tests/migrations.test.ts, mirroring 008):
--   * SECURITY DEFINER: the body runs as its owner (the migration role, which
--     owns the tables and therefore bypasses their RLS — no migration sets
--     FORCE ROW LEVEL SECURITY), so a caller without tenant context can
--     resolve the grid display data.
--   * Fixed search_path = pg_catalog: no schema is searched for objects other
--     than the fully qualified references below.
--   * Fully qualified `public.*` references: no search_path lookup, no
--     hijackable schema in the resolution path.
--   * No dynamic SQL: a plain static SELECT.
--   * REVOKE ... FROM PUBLIC + explicit conditional GRANT to both known app
--     roles (the production app role is stempelpass_runtime; generically we
--     check both stempelpass_runtime and app_role). A role may not exist when
--     this migration runs in a fresh environment; each grant is applied only
--     when the role exists and is re-runnable via the documented one-liners
--     below.
create or replace function public.card_grid_display(p_card_id uuid)
returns table (
  revision integer,
  stamp_count integer,
  stamps_required integer,
  primary_color text,
  secondary_color text,
  reward_issued boolean
)
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select c.revision,
         c.stamp_count::integer,
         r.stamps_required::integer,
         b.primary_color,
         b.secondary_color,
         (c.stamp_count >= r.stamps_required
          and exists (select 1 from public.rewards w
                      where w.tenant_id = c.tenant_id
                        and w.card_id = c.id
                        and w.status = 'issued'))
    from public.cards c
    join public.stamp_rules r
      on r.id = c.rule_id
     and r.tenant_id = c.tenant_id
     and r.active
    left join public.tenant_branding b
      on b.tenant_id = c.tenant_id
   where c.id = p_card_id
     and c.status = 'active'
     and c.deleted_at is null
   limit 1;
$$;
-- No PUBLIC access: only explicitly granted roles may use the escape hatch.
revoke all on function public.card_grid_display(uuid) from public;
-- The app roles may not exist yet in a fresh environment (RLS_AUTH_P1 Teil C
-- documents the blocker). The production app role is stempelpass_runtime;
-- generically we check both known app roles. Each grant is applied only when
-- the role exists; for environments that create the role AFTER this
-- migration, run once per role:
--   grant execute on function public.card_grid_display(uuid) to stempelpass_runtime;
--   grant execute on function public.card_grid_display(uuid) to app_role;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'stempelpass_runtime') then
    execute 'grant execute on function public.card_grid_display(uuid) to stempelpass_runtime';
  end if;
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'grant execute on function public.card_grid_display(uuid) to app_role';
  end if;
end
$$;
