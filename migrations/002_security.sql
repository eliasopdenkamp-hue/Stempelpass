create table if not exists sessions (id uuid primary key default gen_random_uuid(), user_id uuid not null references users(id), tenant_id uuid references tenants(id), token_hash text not null unique, csrf_token_hash text not null, expires_at timestamptz not null, revoked_at timestamptz, created_at timestamptz not null default now());
create table if not exists audit_log (id bigint generated always as identity primary key, tenant_id uuid references tenants(id), actor_user_id uuid references users(id), action text not null, entity_type text not null, entity_id uuid, metadata jsonb not null default '{}', created_at timestamptz not null default now());
create index if not exists sessions_expiry_idx on sessions(expires_at);
create index if not exists audit_tenant_created_idx on audit_log(tenant_id, created_at desc);
-- Audit is append-only for the application role; grant writes through a controlled repository only.
create or replace function prevent_audit_mutation() returns trigger language plpgsql as $$ begin raise exception 'AUDIT_APPEND_ONLY'; end $$;
drop trigger if exists audit_no_update on audit_log; create trigger audit_no_update before update or delete on audit_log for each row execute function prevent_audit_mutation();
