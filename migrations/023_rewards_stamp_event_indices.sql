-- 023: query indices on the two hottest tenant-scoped tables (pre-deployment
-- audit 2026-10-18, RISK #2).
--
-- rewards(tenant_id, card_id): hot in the staff search reward lookup, the
-- dashboard reward map, the stamp NOT EXISTS guard and the staff stats
-- ready/near counts — every lookup filters on tenant + card. The existing
-- unique(tenant_id, idempotency_key) indexes elsewhere do not cover it.
-- stamp_events(tenant_id, created_at desc): hot in the dashboard event list
-- (LIMIT 20) and the 30/60-day retention windows; the existing unique
-- (tenant_id, idempotency_key) index covers only the tenant filter prefix,
-- leaving the sort/time-window as an unsorted scan.
--
-- Both are plain additive B-tree indices (CREATE INDEX IF NOT EXISTS, so a
-- re-run on an already-migrated database is a no-op): no table/column
-- changes, no policies, no functions, no FORCE RLS. No GRANTs needed —
-- PostgreSQL attaches index access privileges to the underlying table, and
-- the runtime role's existing table grants (migrations 014/017/019/020)
-- cover them. Fits the additive-migration rollback rule of 001–022.

create index if not exists rewards_tenant_card_idx on rewards(tenant_id, card_id);
create index if not exists stamp_events_tenant_created_idx on stamp_events(tenant_id, created_at desc);