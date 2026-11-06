SET search_path TO app, extensions, public;

-- A UUID issued by Authentication identifies one account across the User
-- authorization model.  This prevents a concurrent ADMIN/CUSTOMER/HOST
-- projection from silently creating a second subject for the same identity.
CREATE UNIQUE INDEX ux_authorization_subject_auth_account
    ON authorization_subjects(auth_account_id);

ALTER TABLE processed_events
    ADD COLUMN payload_hash char(64),
    ADD COLUMN business_key varchar(220),
    ADD COLUMN event_type varchar(160);

CREATE UNIQUE INDEX ux_processed_events_consumer_business_key
    ON processed_events(consumer_name, business_key)
    WHERE business_key IS NOT NULL;

COMMENT ON COLUMN processed_events.payload_hash IS
    'Canonical event fingerprint used to reject an event-id or business-key collision.';
COMMENT ON COLUMN processed_events.business_key IS
    'Stable aggregate/business deduplication key; null is retained for legacy inbox rows.';
COMMENT ON TABLE processed_events IS
    'Transactional inbox for consumed events. A duplicate is a no-op only when its canonical hash agrees.';
