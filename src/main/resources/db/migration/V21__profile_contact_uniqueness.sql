SET search_path TO app, extensions, public;

-- Contact ownership is scoped by profile type. A polymorphic claim table gives
-- PostgreSQL one real unique key while preserving any legacy duplicate rows for
-- explicit reconciliation instead of silently deleting profile data.
CREATE TABLE profile_contact_claims (
    profile_type varchar(16) NOT NULL,
    contact_kind varchar(16) NOT NULL,
    normalized_value varchar(320) NOT NULL,
    profile_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_type, contact_kind, normalized_value),
    UNIQUE (profile_type, contact_kind, profile_id),
    CONSTRAINT ck_profile_contact_claim_type
        CHECK (profile_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_profile_contact_claim_kind
        CHECK (contact_kind IN ('EMAIL', 'PHONE')),
    CONSTRAINT ck_profile_contact_claim_value
        CHECK (normalized_value = btrim(normalized_value) AND normalized_value <> '')
);

-- DISTINCT ON deterministically assigns an existing contact to the oldest
-- profile. Additional legacy rows remain untouched but cannot be reproduced.
INSERT INTO profile_contact_claims(profile_type, contact_kind, normalized_value, profile_id)
SELECT DISTINCT ON (lower(email::text))
       'CUSTOMER', 'EMAIL', lower(email::text), id
FROM customers WHERE email IS NOT NULL
ORDER BY lower(email::text), created_at, id;

INSERT INTO profile_contact_claims(profile_type, contact_kind, normalized_value, profile_id)
SELECT DISTINCT ON (normalized_phone)
       'CUSTOMER', 'PHONE', normalized_phone, id
FROM customers WHERE normalized_phone IS NOT NULL
ORDER BY normalized_phone, created_at, id;

INSERT INTO profile_contact_claims(profile_type, contact_kind, normalized_value, profile_id)
SELECT DISTINCT ON (lower(email::text))
       'ADMIN', 'EMAIL', lower(email::text), id
FROM admin_users WHERE email IS NOT NULL
ORDER BY lower(email::text), created_at, id;

INSERT INTO profile_contact_claims(profile_type, contact_kind, normalized_value, profile_id)
SELECT DISTINCT ON (normalized_phone)
       'ADMIN', 'PHONE', normalized_phone, id
FROM admin_users WHERE normalized_phone IS NOT NULL
ORDER BY normalized_phone, created_at, id;

INSERT INTO profile_contact_claims(profile_type, contact_kind, normalized_value, profile_id)
SELECT DISTINCT ON (lower(email::text))
       'HOST', 'EMAIL', lower(email::text), id
FROM hosts WHERE email IS NOT NULL
ORDER BY lower(email::text), created_at, id;

INSERT INTO profile_contact_claims(profile_type, contact_kind, normalized_value, profile_id)
SELECT DISTINCT ON (normalized_phone)
       'HOST', 'PHONE', normalized_phone, id
FROM hosts WHERE normalized_phone IS NOT NULL
ORDER BY normalized_phone, created_at, id;

CREATE OR REPLACE FUNCTION claim_profile_contact(
    requested_profile_type varchar,
    requested_contact_kind varchar,
    requested_value varchar,
    requested_profile_id uuid
) RETURNS void
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $$
DECLARE
    canonical_value varchar(320);
    owner_id uuid;
BEGIN
    IF requested_value IS NULL OR btrim(requested_value) = '' THEN
        RETURN;
    END IF;
    canonical_value := CASE requested_contact_kind
        WHEN 'EMAIL' THEN lower(btrim(requested_value))
        ELSE btrim(requested_value)
    END;

    INSERT INTO profile_contact_claims(profile_type, contact_kind, normalized_value, profile_id)
    VALUES (requested_profile_type, requested_contact_kind, canonical_value, requested_profile_id)
    ON CONFLICT (profile_type, contact_kind, normalized_value) DO NOTHING;

    SELECT profile_id INTO owner_id
    FROM profile_contact_claims
    WHERE profile_type = requested_profile_type
      AND contact_kind = requested_contact_kind
      AND normalized_value = canonical_value;

    IF owner_id IS DISTINCT FROM requested_profile_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = requested_contact_kind || ' already belongs to another profile of this type',
            CONSTRAINT = CASE requested_contact_kind
                WHEN 'EMAIL' THEN 'ux_profile_contact_email'
                ELSE 'ux_profile_contact_phone'
            END;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION sync_profile_contact_claims() RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $$
DECLARE
    resolved_profile_type varchar(16);
BEGIN
    resolved_profile_type := CASE TG_TABLE_NAME
        WHEN 'customers' THEN 'CUSTOMER'
        WHEN 'admin_users' THEN 'ADMIN'
        WHEN 'hosts' THEN 'HOST'
        ELSE NULL
    END;
    IF resolved_profile_type IS NULL THEN
        RAISE EXCEPTION 'Unsupported profile contact source table: %', TG_TABLE_NAME;
    END IF;

    IF TG_OP = 'DELETE' THEN
        DELETE FROM profile_contact_claims
        WHERE profile_type = resolved_profile_type AND profile_id = OLD.id;
        RETURN OLD;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.email IS DISTINCT FROM NEW.email THEN
            DELETE FROM profile_contact_claims
            WHERE profile_type = resolved_profile_type AND contact_kind = 'EMAIL'
              AND profile_id = OLD.id;
            PERFORM claim_profile_contact(resolved_profile_type, 'EMAIL', NEW.email::text, NEW.id);
        END IF;
        IF OLD.normalized_phone IS DISTINCT FROM NEW.normalized_phone THEN
            DELETE FROM profile_contact_claims
            WHERE profile_type = resolved_profile_type AND contact_kind = 'PHONE'
              AND profile_id = OLD.id;
            PERFORM claim_profile_contact(resolved_profile_type, 'PHONE', NEW.normalized_phone, NEW.id);
        END IF;
        RETURN NEW;
    END IF;

    PERFORM claim_profile_contact(resolved_profile_type, 'EMAIL', NEW.email::text, NEW.id);
    PERFORM claim_profile_contact(resolved_profile_type, 'PHONE', NEW.normalized_phone, NEW.id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_customer_contact_claims
    BEFORE INSERT OR UPDATE OR DELETE ON customers
    FOR EACH ROW EXECUTE FUNCTION sync_profile_contact_claims();
CREATE TRIGGER trg_admin_contact_claims
    BEFORE INSERT OR UPDATE OR DELETE ON admin_users
    FOR EACH ROW EXECUTE FUNCTION sync_profile_contact_claims();
CREATE TRIGGER trg_host_contact_claims
    BEFORE INSERT OR UPDATE OR DELETE ON hosts
    FOR EACH ROW EXECUTE FUNCTION sync_profile_contact_claims();

COMMENT ON TABLE profile_contact_claims IS
    'Race-safe ownership registry for normalized email and phone, unique inside each profile type.';
