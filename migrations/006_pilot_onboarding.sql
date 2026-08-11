-- Pilot onboarding metadata and auditable administrative changes.
create table tenant_entry_points (
  tenant_id uuid primary key references tenants(id) on delete cascade,
  public_key text not null unique,
  join_path text not null unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table tenant_entry_points enable row level security;
create policy tenant_entry_points_isolation on tenant_entry_points using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create index tenant_entry_points_public_key on tenant_entry_points(public_key);

-- Audit is append-only in application code and tenant scoped where applicable.
alter table audit_log enable row level security;
drop policy if exists audit_log_isolation on audit_log;
create policy audit_log_isolation on audit_log using (tenant_id is null or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) with check (tenant_id is null or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
