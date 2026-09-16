-- Tenant branding: hosted logo URL for the Google Wallet class (programLogo).
--
-- The legacy icon_asset_id / logo_asset_id UUID columns stay as asset-store
-- references (no asset store exists yet). The Google Wallet LoyaltyClass API
-- needs a PUBLICLY HOSTED https URL for programLogo, so tenant branding gains
-- its own text column; the Staff-UI branding form accepts an https URL string.
-- Column-level grants are not needed: the app role's table-level DML grants
-- (migration 014) cover new columns automatically, and RLS policy is table-level.
alter table tenant_branding add column logo_url text;