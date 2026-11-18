SET search_path TO app, extensions, public;

ALTER TABLE customers
    ALTER COLUMN nationality_code SET DEFAULT 'VNM';

ALTER TABLE profile_identity_documents
    DROP CONSTRAINT ck_profile_identity_document;

ALTER TABLE profile_identity_documents
    ADD CONSTRAINT ck_profile_identity_document CHECK (
        (document_country = 'VN' AND document_type = 'CCCD')
        OR (
            document_country ~ '^[A-Z]{2}$'
            AND document_type = 'PASSPORT'
        )
    );

COMMENT ON COLUMN customers.nationality_code IS
    'ISO 3166-1 alpha-3 nationality. New customer profiles default to VNM.';

COMMENT ON COLUMN profile_identity_documents.document_country IS
    'ISO 3166-1 alpha-2 issuing country used as part of the deterministic Vault lookup namespace.';

COMMENT ON COLUMN profile_identity_documents.document_type IS
    'Temporary supported catalog: CCCD for VN, or PASSPORT for any ISO issuing country.';
