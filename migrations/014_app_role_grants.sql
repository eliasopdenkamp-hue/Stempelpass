-- 014: grant the minimal runtime privileges needed after migrations 008–013.
--
-- This migration is intentionally additive and idempotent. It does not create,
-- alter, downgrade, or replace any role. If app_role is not present yet, the
-- grants are skipped and must be applied after the dedicated app role exists.
-- Runtime DATABASE_URL must ultimately use that dedicated non-owner,
-- non-BYPASSRLS role; an owner/privileged migration connection is not suitable.

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'grant usage on schema public to app_role';
    execute 'grant select, insert, update on table public.card_creation_idempotency to app_role';
    execute 'grant execute on function public.resolve_entry_point(text) to app_role';
    execute 'grant execute on function public.resolve_session_user(text) to app_role';
    execute 'grant execute on function public.membership_mfa_required(uuid) to app_role';
  end if;
end
$$;
