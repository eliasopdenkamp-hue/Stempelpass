-- 016: Tenantless staff-UI tenant resolution via a minimal-privilege resolver.
--
-- The staff web UI (GET /staff, redirect to /staff/:tenantId after login) must
-- answer "which active tenants does this session user belong to?" BEFORE any
-- tenant context exists. A direct read of `tenant_memberships`
-- (tenant-isolation RLS since 001) under RLS returns zero rows outside a
-- tenant context, exactly like the pre-010 login bootstrap problem. This
-- SECURITY DEFINER function is the same minimal-privilege escape hatch as
-- resolve_entry_point (008), resolve_session_user (009) and
-- membership_mfa_required (010): it accepts ONLY a user id and returns ONLY
-- (tenant_id, role) for that user's active memberships. The app role needs NO
-- table-level privilege on tenant_memberships for the staff entry — just
-- EXECUTE on this one function.
--
-- Hardening properties (mirroring 010, pinned by tests/migrations.test.ts):
--   * SECURITY DEFINER: runs as its owner (the migration role, which owns the
--     tables and therefore bypasses their RLS — no migration sets FORCE ROW
--     LEVEL SECURITY), so the tenantless staff entry can resolve the list.
--   * Fixed search_path = pg_catalog: no schema is searched for objects other
--     than the fully qualified table reference below.
--   * Fully qualified `public.tenant_memberships`: no search_path lookup,
--     no hijackable schema in the resolution path.
--   * No dynamic SQL in the body: a plain static SELECT.
--   * Column minimization: reads only m.tenant_id, m.role, m.status and
--     m.created_at — never email, user ids of others, MFA state or any other
--     membership/user column. Returns ONLY tenant_id + role; nothing else.
--   * p_user_id is typed uuid, so the driver/type system rejects malformed
--     input before the function body runs.
--   * REVOKE ... FROM PUBLIC + explicit conditional GRANT only to the app role.
--
-- Semantics: exactly the user's ACTIVE memberships (status='active'),
-- ordered by membership creation. A user with no active memberships returns
-- zero rows. Role values come from the membership row's role check
-- constraint ('owner','admin','staff','viewer') — never free text.
create or replace function public.resolve_user_tenants(p_user_id uuid)
returns table (tenant_id uuid, role text)
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select m.tenant_id, m.role::text
    from public.tenant_memberships m
   where m.user_id = p_user_id
     and m.status = 'active'
   order by m.created_at
$$;
-- No PUBLIC access: only explicitly granted roles may use the escape hatch.
revoke all on function public.resolve_user_tenants(uuid) from public;
-- The production app role may not exist yet in this environment (RLS_AUTH_P1
-- Teil C documents the blocker). The grant is applied when the role exists;
-- for environments that create the app role AFTER this migration, run once:
--   grant execute on function public.resolve_user_tenants(uuid) to app_role;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'grant execute on function public.resolve_user_tenants(uuid) to app_role';
  end if;
end
$$;