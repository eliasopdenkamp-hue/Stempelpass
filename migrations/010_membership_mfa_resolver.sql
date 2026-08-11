-- 010: Tenantless login MFA bootstrap via a minimal-privilege resolver.
--
-- B1 (login MFA bootstrap under RLS): the unauthenticated /api/auth/login
-- route has NO tenant context and must never set app.tenant_id, so a direct
-- read of `tenant_memberships` (tenant-isolation RLS since 001) under RLS
-- returns zero rows. The old inline `bool_or` aggregate then yielded NULL and
-- the fail-closed guard (MFA_BOOTSTRAP_UNVERIFIED) blocked EVERY login.
-- This SECURITY DEFINER function is the single, minimal-privilege escape
-- hatch — the same pattern as resolve_entry_point (008) and
-- resolve_session_user (009): it accepts ONLY a user id and returns ONLY the
-- boolean "this user's active owner/admin memberships require MFA". The app
-- role needs NO table-level privilege on tenant_memberships or users for the
-- login bootstrap — just EXECUTE on this one function.
--
-- Hardening properties (pinned by tests/migrations.test.ts and
-- tests/membership-mfa-rls.test.ts):
--   * SECURITY DEFINER: the body runs as its owner (the migration role, which
--     owns the tables and therefore bypasses their RLS — no migration sets
--     FORCE ROW LEVEL SECURITY), so the tenantless login can resolve the flag.
--   * Fixed search_path = pg_catalog: no schema is searched for objects other
--     than the fully qualified table references below.
--   * Fully qualified `public.tenant_memberships` / `public.users`: no
--     search_path lookup, no hijackable schema in the resolution path.
--   * No dynamic SQL in the body: a plain static SELECT EXISTS.
--   * Returns ONLY a boolean and NEVER NULL: EXISTS yields true/false for any
--     input, so an absent membership row is a deliberate `false` ("no active
--     owner/admin membership requires MFA") and can never be confused with
--     "MFA not required" because the call itself failed. The application
--     still fail-closes when the function/result is missing (missing function
--     → query error; no row / NULL result → MFA_BOOTSTRAP_UNVERIFIED).
--   * Column minimization: the body reads only m.role, m.status,
--     m.mfa_required and u.mfa_required — never email, password_hash,
--     mfa_secret_ciphertext or any other user/membership column.
--   * p_user_id is typed uuid, so the driver/type system rejects malformed
--     input before the function body runs (no regex guard needed).
--   * REVOKE ... FROM PUBLIC + explicit conditional GRANT only to the app role.
--
-- Semantics match the previous inline aggregate exactly: required = EXISTS an
-- active membership with role owner/admin where the membership OR the user
-- carries mfa_required = true. A user with only staff/viewer memberships, or
-- with no active memberships at all, resolves to false.
create or replace function public.membership_mfa_required(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select exists (
    select 1
      from public.tenant_memberships m
      join public.users u on u.id = m.user_id
     where m.user_id = p_user_id
       and m.status = 'active'
       and m.role in ('owner', 'admin')
       and (m.mfa_required or u.mfa_required)
  )
$$;
-- No PUBLIC access: only explicitly granted roles may use the escape hatch.
revoke all on function public.membership_mfa_required(uuid) from public;
-- The production app role may not exist yet in this environment (RLS_AUTH_P1
-- Teil C documents the blocker). The grant is applied when the role exists;
-- for environments that create the app role AFTER this migration, run once:
--   grant execute on function public.membership_mfa_required(uuid) to app_role;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'grant execute on function public.membership_mfa_required(uuid) to app_role';
  end if;
end
$$;
