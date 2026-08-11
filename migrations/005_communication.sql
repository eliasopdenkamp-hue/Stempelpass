-- Tenant-scoped communication preferences, consent history, and minimized delivery logs.
create table communication_preferences (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  customer_id uuid not null references customers(id),
  purpose text not null check (purpose in ('service','marketing')),
  channel text not null check (channel in ('email')),
  opted_in boolean not null default false,
  opted_in_at timestamptz,
  withdrawn_at timestamptz,
  updated_at timestamptz not null default now(),
  unique (tenant_id, customer_id, purpose, channel)
);
create index communication_preferences_lookup on communication_preferences(tenant_id, customer_id, purpose, channel);

create table communication_consent_events (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references tenants(id),
  customer_id uuid not null references customers(id),
  purpose text not null check (purpose in ('service','marketing')),
  channel text not null check (channel in ('email')),
  action text not null check (action in ('opt_in','withdraw','unsubscribe')),
  source text not null,
  occurred_at timestamptz not null default now()
);
create index communication_consent_events_lookup on communication_consent_events(tenant_id, customer_id, occurred_at desc);

create table communication_message_logs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  customer_id uuid references customers(id),
  purpose text not null check (purpose in ('service','marketing')),
  channel text not null check (channel in ('email')),
  message_type text not null,
  recipient_hash text not null,
  status text not null check (status in ('not_configured','queued','sent','failed','blocked')),
  provider_message_id text,
  failure_code text,
  created_at timestamptz not null default now()
);
create index communication_message_logs_lookup on communication_message_logs(tenant_id, created_at desc);

alter table communication_preferences enable row level security;
alter table communication_consent_events enable row level security;
alter table communication_message_logs enable row level security;
create policy communication_preferences_tenant_isolation on communication_preferences using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy communication_consent_events_tenant_isolation on communication_consent_events using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy communication_message_logs_tenant_isolation on communication_message_logs using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
