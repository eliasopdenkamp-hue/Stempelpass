-- 020: password-reset hardening (Security-Review-Report 91292cdf) —
--      SECURITY DEFINER `reset_user_password` instead of a direct UPDATE grant.
--
-- Migration 019 granted the runtime role direct UPDATE on public.users so the
-- unauthenticated reset-confirm route could rotate users.password_hash. That
-- grant is wider than the write needs: `users` rows (email, display_name, MFA
-- columns) are otherwise SELECT-only for the runtime role, so a compromised
-- request path could UPDATE any column of any user row. Defense-in-depth: the
-- rotation moves into a dedicated SECURITY DEFINER function (the established
-- minimal-privilege escape-hatch pattern of 008/009/010/016) and the direct
-- table grant is revoked (rls-verify REQUIRED_GRANTS.users returns to
-- ['SELECT']).
--
-- The function is ATOMIC in the TOCTOU sense the review flagged (server.ts
-- reset confirm): token resolve + validity check + consume (consumed_at) +
-- password write happen in ONE statement (data-modifying CTE). Two concurrent
-- confirms of the same token serialize on the token row lock; the loser sees
-- consumed_at already set, returns 0 rows and the caller answers the neutral
-- RESET_TOKEN_INVALID. It returns ONLY the owning user_id (never the hash, the
-- token or the email) and is executed by the runtime role as the caller while
-- the owner privileges of the SECURITY DEFINER function do the write — the
-- runtime role itself never holds UPDATE on users.
create or replace function public.reset_user_password(p_token_hash text, p_password_hash text)
returns table (user_id uuid)
language sql
volatile
security definer
set search_path = pg_catalog
as $$
  with consume as (
    update public.password_reset_tokens
       set consumed_at = now()
     where p_token_hash ~ '^[a-f0-9]{64}$'
       and public.password_reset_tokens.token_hash = p_token_hash
       and public.password_reset_tokens.consumed_at is null
       and public.password_reset_tokens.expires_at > now()
     returning public.password_reset_tokens.user_id
  )
  update public.users u
     set password_hash = p_password_hash,
         updated_at = now()
    from consume c
   where u.id = c.user_id
     and u.status = 'active'
   returning u.id
$$;
-- No PUBLIC access: only explicitly granted roles may use the escape hatch.
revoke all on function public.reset_user_password(text, text) from public;
-- Conditional grants/revokes (convention 008/009/010/014/016/017/019): the
-- dedicated runtime role is provisioned out-of-band; an unconditional GRANT or
-- REVOKE naming an absent role would abort the migration run.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'stempelpass_runtime') then
    execute 'revoke update on public.users from stempelpass_runtime';
    execute 'grant execute on function public.reset_user_password(text, text) to stempelpass_runtime';
  end if;
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'revoke update on public.users from app_role';
    execute 'grant execute on function public.reset_user_password(text, text) to app_role';
  end if;
end
$$;