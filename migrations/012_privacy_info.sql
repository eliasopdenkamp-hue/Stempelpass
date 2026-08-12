-- 012: DSGVO Art. 13 contact on the public web card (DSGVO_PILOT.md §4).
--
-- tenant_branding.privacy_email is the OPTIONAL contact address for data
-- subject requests (Auskunft/Berichtigung/Löschung/Widerspruch). Nullable on
-- purpose — no new mandatory field: when it is NULL the public card simply
-- omits the contact line (no placeholder invented). The controller name comes
-- from tenants.legal_name (migration 001); no new column for that.
alter table tenant_branding add column privacy_email text;
