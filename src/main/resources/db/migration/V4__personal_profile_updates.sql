SET search_path TO app, extensions, public;

ALTER TABLE audit_events
    ADD COLUMN reason varchar(500);

CREATE TABLE profile_update_requests (
    idempotency_key varchar(160) PRIMARY KEY,
    request_hash char(64) NOT NULL,
    admin_user_id uuid NOT NULL REFERENCES admin_users(id),
    resulting_version bigint NOT NULL CHECK (resulting_version > 0),
    result_display_name varchar(180) NOT NULL,
    result_email varchar(320) NOT NULL,
    result_contact_phone varchar(16),
    result_avatar_media_id uuid,
    result_updated_at timestamptz NOT NULL,
    correlation_id varchar(160) NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_profile_update_admin
    ON profile_update_requests(admin_user_id, completed_at DESC);

COMMENT ON TABLE profile_update_requests IS
    'Idempotency ledger for Backoffice self-service profile updates; avatar_media_id remains an external Media reference.';
