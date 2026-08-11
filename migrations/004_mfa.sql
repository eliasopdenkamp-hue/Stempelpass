alter table users add column if not exists mfa_required boolean not null default false;
alter table users add column if not exists mfa_enabled boolean not null default false;
alter table tenant_memberships add column if not exists mfa_required boolean not null default false;
alter table tenant_memberships add column if not exists mfa_enabled boolean not null default false;
alter table users add column if not exists mfa_secret_ciphertext text;
alter table sessions add column if not exists mfa_verified boolean not null default false;
-- MFA secrets are ciphertext produced by the configured secret provider. Plaintext TOTP secrets must never be stored.
