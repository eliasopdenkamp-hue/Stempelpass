-- 009: Session rows user-scoped (RLS) and audit_log policy split.
--
-- B2 (sessions without RLS): `sessions` holds per-user credentials
-- (token_hash, csrf_token_hash). RLS is enabled with a USER-scoped policy:
-- a row is visible/writable only when the transaction carries the owning
-- user's id in `app.user_id`. Tenant scoping is deliberately NOT part of
-- this policy: a session belongs to a user, and the tenant boundary is
-- enforced by the tenant_memberships join in the authenticated query
-- (auth() in server.ts) plus tenant_memberships' own tenant RLS. The net
-- effect is that a session row can never be seen or changed under a
-- different user's context, regardless of tenant.
alter table sessions enable row level security;
drop policy if exists sessions_user_isolation on sessions;
create policy sessions_user_isolation on sessions
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);

-- Identity bootstrap: auth() must resolve the owning user_id from the
-- session token BEFORE it can set app.user_id (the RLS policy needs the
-- user id to see the row). Analog zum /join-Entry-Point-Resolver (008) ist
-- dies der einzige minimalprivilegierte Ausweg: it accepts ONLY a token hash
-- and returns ONLY the owning user_id for the exact matching row. Sensitive
-- columns (csrf_token_hash, expires_at, revoked_at, ...) are never returned
-- here; the follow-up session read in auth() runs under full RLS with
-- app.user_id set. Possession of the token hash is the authentication
-- factor, so an exact-match lookup reveals no secret the caller does not
-- already hold.
--
-- The app role needs NO table-level privilege on sessions for this lookup —
-- only EXECUTE on this one function. The function runs as its owner (the
-- migration role, which owns the table); sessions has NO FORCE ROW LEVEL
-- SECURITY, so the owner bypass applies only inside this function (see
-- RLS_AUTH_P1.md Teil E for the owner/FORCE decision).
create or replace function public.resolve_session_user(p_token_hash text)
returns table (user_id uuid)
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select public.sessions.user_id
    from public.sessions
   where public.sessions.token_hash = p_token_hash
     and p_token_hash ~ '^[a-f0-9]{64}$'
$$;
-- No PUBLIC access: only explicitly granted roles may use the escape hatch.
revoke all on function public.resolve_session_user(text) from public;
-- The production app role may not exist yet in this environment (RLS_AUTH_P1
-- Teil C documents the blocker). The grant is applied when the role exists;
-- for environments that create the app role AFTER this migration, run once:
--   grant execute on function public.resolve_session_user(text) to app_role;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'grant execute on function public.resolve_session_user(text) to app_role';
  end if;
end
$$;

-- B3 (audit_log NULL-tenant branch): migration 006 used a single policy
-- `tenant_id is null or tenant_id = app.tenant_id`, which granted global
-- rows (tenant_id IS NULL) to EVERY context and granted all rows to the
-- context-free case. The policy is split into two OR-ed policies:
--   * tenant rows (tenant_id NOT NULL) are only visible/writable in the
--     matching app.tenant_id context;
--   * global rows (tenant_id IS NULL) are only visible/writable when NO
--     tenant context is set at all.
-- Normal appendAudit calls (configurePilot/setStaff) run inside
-- repository.transaction(tenantId, ...), which sets app.tenant_id, so
-- tenant-scoped rows still pass the WITH CHECK unchanged.
alter table audit_log enable row level security;
drop policy if exists audit_log_isolation on audit_log;
create policy audit_log_tenant_isolation on audit_log
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy audit_log_global_isolation on audit_log
  using (tenant_id is null and nullif(current_setting('app.tenant_id', true), '') is null)
  with check (tenant_id is null and nullif(current_setting('app.tenant_id', true), '') is null);
