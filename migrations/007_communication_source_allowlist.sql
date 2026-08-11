-- Keep consent provenance bounded even if a future write path bypasses the application validator.
alter table communication_consent_events
  add constraint communication_consent_events_source_check
  check (source in ('web_form', 'unsubscribe_link', 'admin_action', 'system'));
