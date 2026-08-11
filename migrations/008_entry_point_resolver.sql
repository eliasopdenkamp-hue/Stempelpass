-- Public entry-point resolution for GET /join/:publicKey.
--
-- `tenant_entry_points` is protected by tenant-isolation RLS (006). The
-- unauthenticated /join route has no tenant context and must never set
-- app.tenant_id, so a direct table read under RLS would hide every row.
-- This SECURITY DEFINER function is the single, minimal-privilege escape
-- hatch: it accepts ONLY a public key and returns ONLY (tenant_id,
-- join_path) for the exact matching row. The app role needs NO table-level
-- privilege on tenant_entry_points — just EXECUTE on this one function.
--
-- Hardening properties (pinned by tests/entry-point-rls.test.ts):
--   * SECURITY DEFINER: the function body runs as its owner (the migration
--     role, which owns the table and therefore bypasses the table's RLS —
--     migration 006 sets no FORCE ROW LEVEL SECURITY), so a caller without
--     tenant context can resolve the join link.
--   * Fixed search_path = pg_catalog: no schema is searched for objects
--     other than the fully qualified table reference below.
--   * Fully qualified `public.tenant_entry_points`: no search_path lookup,
--     no hijackable schema in the resolution path.
--   * No dynamic SQL in the body: a plain static SELECT.
--   * The public_key format guard (`^[a-f0-9]{32}$`) is defense in depth;
--     the application validates the same format before calling.
--   * REVOKE ... FROM PUBLIC + explicit GRANT only to the app role.
--
-- NOTE: production migrations run in schema `public` (runMigrations uses
-- the connection's default search_path), so `public.tenant_entry_points`
-- exists when this migration runs and the reference resolves (SQL function
-- bodies are resolved at create time). The Neon integration harness applies
-- migrations in a per-run temporary schema and rewrites the `public.`
-- qualifier onto that schema (see tests/db.integration.test.ts) so this
-- migration applies there too.
create or replace function public.resolve_entry_point(p_public_key text)
returns table (tenant_id uuid, join_path text)
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select public.tenant_entry_points.tenant_id,
         public.tenant_entry_points.join_path
    from public.tenant_entry_points
   where public.tenant_entry_points.public_key = p_public_key
     and p_public_key ~ '^[a-f0-9]{32}$'
$$;
-- No PUBLIC access: only explicitly granted roles may use the escape hatch.
revoke all on function public.resolve_entry_point(text) from public;
-- The production app role may not exist yet in this environment (RLS_AUTH_P1
-- Teil C documents the blocker). The grant is applied when the role exists;
-- for environments that create the app role AFTER this migration, run once:
--   grant execute on function public.resolve_entry_point(text) to app_role;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'grant execute on function public.resolve_entry_point(text) to app_role';
  end if;
end
$$;
