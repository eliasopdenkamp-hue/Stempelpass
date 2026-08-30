-- 015: operator/legal hold for customer retention.
-- A held customer is never selected by the out-of-band hard-delete job until
-- the legal/operational hold is explicitly cleared by an authorized operator.
alter table customers add column legal_retention_hold boolean not null default false;
create index customers_hard_delete_candidates on customers (deleted_at) where deleted_at is not null and legal_retention_hold = false;
