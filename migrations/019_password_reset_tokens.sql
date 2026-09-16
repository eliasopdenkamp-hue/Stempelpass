-- 019: self-service password reset ("Passwort vergessen", owner wish).
--
-- Data model: one row per issued reset link. The raw token (randomToken(),
-- 32 random bytes base64url) is NEVER stored — only its SHA-256 hex digest
-- (hashSessionToken), exactly like sessions.token_hash. Tokens expire after
-- 60 minutes (expires_at) and are single-use (consumed_at).
--
-- RLS: user-scoped like sessions (migration 009). A row is visible/writable
-- only when the transaction carries the owning user's id in app.user_id. The
-- unauthenticated request path (POST /api/auth/reset/request) sets app.user_id
-- from the SERVER-SIDE email lookup before inserting — exactly the login
-- session-insert pattern (server.ts login route) — so a client can never pick
-- a target user id ("the owner of the email" is chosen by the DB, never by
-- the requester; raw user UUIDs never leave the server).
--
-- Identity bootstrap: auth-less flows (GET /reset/:token, POST
-- /api/auth/reset/confirm) resolve the owning user_id from the token hash via
-- this SECURITY DEFINER function before any app.user_id context exists — the
-- same minimal-privilege escape hatch as resolve_session_user (009). It
-- accepts ONLY a 64-hex token hash, returns ONLY user_id, and only for
-- unconsumed, unexpired tokens. Possession of the raw token (which only ever
-- reaches the account owner's mailbox) is the authentication factor.
--
-- WARNING (2026-09-16, customers-017 incident class): the runtime role has
-- NEVER held UPDATE on public.users (rls-verify REQUIRED_GRANTS had
-- users: ['SELECT']). Reset confirm must write password_hash — without this
-- grant the write would be a permission-denied 500 exactly like the
-- 2026-09-15 customers INSERT gap. Migration 019 grants UPDATE on users to
-- the runtime role (and app_role), and src/rls-verify.ts REQUIRED_GRANTS is
-- updated to users: ['SELECT', 'UPDATE'] so the production check fails loudly
-- when the grant is missing.
create table password_reset_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id),
  token_hash text not null unique,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);
alter table password_reset_tokens enable row level security;
drop policy if exists password_reset_tokens_user_isolation on password_reset_tokens;
create policy password_reset_tokens_user_isolation on password_reset_tokens
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);

create or replace function public.resolve_password_reset_user(p_token_hash text)
returns table (user_id uuid)
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select public.password_reset_tokens.user_id
    from public.password_reset_tokens
   where public.password_reset_tokens.token_hash = p_token_hash
     and p_token_hash ~ '^[a-f0-9]{64}$'
     and public.password_reset_tokens.consumed_at is null
     and public.password_reset_tokens.expires_at > now()
$$;
-- No PUBLIC access: only explicitly granted roles may use the escape hatch.
revoke all on function public.resolve_password_reset_user(text) from public;
-- Conditional grants (convention 008/009/010/014/016/017): the dedicated
-- runtime role is provisioned out-of-band; an unconditional GRANT to an
-- absent role would abort the migration run.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'stempelpass_runtime') then
    execute 'grant execute on function public.resolve_password_reset_user(text) to stempelpass_runtime';
    execute 'grant select, insert, update on table public.password_reset_tokens to stempelpass_runtime';
    execute 'grant update on public.users to stempelpass_runtime';
  end if;
  if exists (select 1 from pg_roles where rolname = 'app_role') then
    execute 'grant execute on function public.resolve_password_reset_user(text) to app_role';
    execute 'grant select, insert, update on table public.password_reset_tokens to app_role';
    execute 'grant update on public.users to app_role';
  end if;
end
$$;