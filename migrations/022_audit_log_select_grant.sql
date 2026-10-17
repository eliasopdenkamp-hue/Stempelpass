-- 022: audit_log SELECT for the runtime role (2026-10-17 incident).
--
-- Root cause of the production 500 on POST /api/auth/reset/confirm: the
-- handler's audit INSERT is idempotence-guarded with `where not exists
-- (select 1 from audit_log where ...)` (Security-Review 91292cdf backstop),
-- and that SUBQUERY needs SELECT on audit_log. Migration 009/014 granted the
-- runtime role INSERT (and the RLS policies from 009 scope row visibility),
-- but SELECT was never granted. Under the least-privilege runtime role the
-- statement failed with `permission denied for table audit_log`; the
-- transaction rolled back and the route answered INTERNAL_ERROR although
-- token and password were valid (the token was NOT consumed — a re-submit
-- with the same link succeeds after this fix).
--
-- SELECT is the MINIMAL missing privilege: the RLS policies (tenant-scoped +
-- global-isolation, migration 009) still filter every row the runtime role
-- may actually see, and the NOT-EXISTS guard only reads the same rows the
-- INSERT path already touches. app_role receives the same minimal grant.
-- Conditional grants (convention 008/009/010/014/016/017/019/020): the roles
-- are provisioned out-of-band; an unconditional GRANT naming an absent role
-- would abort the migration run.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'stempelpass_runtime') then
    execute 'grant select on public.audit_log to stempelpass_runtime';
  end if;
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'grant select on public.audit_log to app_role';
  end if;
end
$$;