-- Idempotent card creation: retain the one-time token encrypted so a lost
-- response can be safely replayed without ever storing the raw token.
create table card_creation_idempotency (
  tenant_id uuid not null references tenants(id),
  idempotency_key text not null,
  request_fingerprint text not null,
  card_id uuid not null references cards(id),
  token_ciphertext text not null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, idempotency_key)
);
alter table card_creation_idempotency enable row level security;
create policy tenant_isolation on card_creation_idempotency using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
