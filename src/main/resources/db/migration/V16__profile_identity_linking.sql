SET search_path TO app, extensions, public;

-- A profile may exist before an interactive account. CCCD is never persisted in
-- plaintext: Vault Transit owns encryption and deterministic HMAC operations.
-- The same document may identify one CUSTOMER, one HOST and one ADMIN profile,
-- while remaining unique inside each profile type.
CREATE TABLE profile_identity_documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_type varchar(16) NOT NULL,
    profile_id uuid NOT NULL,
    document_country char(2) NOT NULL DEFAULT 'VN',
    document_type varchar(24) NOT NULL DEFAULT 'CCCD',
    lookup_hmac text NOT NULL,
    lookup_key_version integer NOT NULL CHECK (lookup_key_version > 0),
    encrypted_value text NOT NULL,
    encryption_key_version integer NOT NULL CHECK (encryption_key_version > 0),
    assurance_level varchar(32) NOT NULL DEFAULT 'SELF_DECLARED',
    verified_at timestamptz,
    verified_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE SET NULL,
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_profile_identity_type
        CHECK (profile_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_profile_identity_document
        CHECK (document_country = 'VN' AND document_type = 'CCCD'),
    CONSTRAINT ck_profile_identity_hmac
        CHECK (lookup_hmac ~ '^vault:v[0-9]+:[A-Za-z0-9+/=_-]+$'),
    CONSTRAINT ck_profile_identity_ciphertext
        CHECK (encrypted_value ~ '^vault:v[0-9]+:'),
    CONSTRAINT ck_profile_identity_assurance
        CHECK (assurance_level IN ('SELF_DECLARED', 'CONTACT_VERIFIED', 'MANUALLY_VERIFIED', 'E_KYC_VERIFIED')),
    UNIQUE (profile_type, profile_id, document_country, document_type),
    UNIQUE (profile_type, document_country, document_type, lookup_hmac)
);

CREATE INDEX ix_profile_identity_lookup
    ON profile_identity_documents(profile_type, document_country, document_type, lookup_hmac);

CREATE TABLE profile_account_links (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_type varchar(16) NOT NULL,
    profile_id uuid NOT NULL,
    auth_account_id uuid NOT NULL,
    status varchar(24) NOT NULL,
    link_method varchar(32) NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    evidence_verified_at timestamptz,
    approved_at timestamptz,
    approved_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE SET NULL,
    linked_at timestamptz,
    revoked_at timestamptz,
    reason varchar(500),
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_profile_account_link_type
        CHECK (profile_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_profile_account_link_status
        CHECK (status IN ('REQUESTED', 'CHALLENGE_ISSUED', 'EVIDENCE_VERIFIED', 'APPROVAL_PENDING',
                          'LINKED', 'REJECTED', 'EXPIRED', 'CONFLICT', 'REVOKED')),
    CONSTRAINT ck_profile_account_link_method
        CHECK (link_method IN ('CCCD_EMAIL_OTP', 'INVITATION_CCCD_EMAIL_OTP', 'CUSTOMER_SELF_CREATE'))
);

CREATE UNIQUE INDEX ux_profile_account_link_profile_active
    ON profile_account_links(profile_type, profile_id)
    WHERE status IN ('REQUESTED', 'CHALLENGE_ISSUED', 'EVIDENCE_VERIFIED', 'APPROVAL_PENDING', 'LINKED');
CREATE UNIQUE INDEX ux_profile_account_link_account_active
    ON profile_account_links(profile_type, auth_account_id)
    WHERE status IN ('REQUESTED', 'CHALLENGE_ISSUED', 'EVIDENCE_VERIFIED', 'APPROVAL_PENDING', 'LINKED');
CREATE INDEX ix_profile_account_link_review
    ON profile_account_links(profile_type, status, requested_at);

CREATE TABLE profile_link_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id uuid NOT NULL REFERENCES profile_account_links(id) ON DELETE RESTRICT,
    recipient_email citext NOT NULL,
    masked_recipient varchar(180) NOT NULL,
    otp_hmac text NOT NULL,
    otp_key_version integer NOT NULL CHECK (otp_key_version > 0),
    delivery_ciphertext text NOT NULL,
    delivery_key_version integer NOT NULL CHECK (delivery_key_version > 0),
    status varchar(24) NOT NULL DEFAULT 'PENDING_DELIVERY',
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 20),
    expires_at timestamptz NOT NULL,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_profile_link_challenge_status
        CHECK (status IN ('PENDING_DELIVERY', 'DELIVERED', 'VERIFIED', 'EXPIRED', 'LOCKED', 'CANCELLED')),
    CONSTRAINT ck_profile_link_challenge_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_profile_link_challenge_hmac
        CHECK (otp_hmac ~ '^vault:v[0-9]+:[A-Za-z0-9+/=_-]+$'),
    CONSTRAINT ck_profile_link_challenge_ciphertext
        CHECK (delivery_ciphertext ~ '^vault:v[0-9]+:')
);

CREATE UNIQUE INDEX ux_profile_link_challenge_open
    ON profile_link_challenges(link_id)
    WHERE status IN ('PENDING_DELIVERY', 'DELIVERED');
CREATE INDEX ix_profile_link_challenge_expiry
    ON profile_link_challenges(status, expires_at);

CREATE TABLE profile_link_policies (
    account_type varchar(16) PRIMARY KEY,
    policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    link_deadline interval NOT NULL,
    otp_ttl interval NOT NULL,
    max_otp_attempts integer NOT NULL CHECK (max_otp_attempts BETWEEN 1 AND 20),
    requires_approval boolean NOT NULL,
    disable_grace_period interval NOT NULL,
    purge_after interval NOT NULL,
    active boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE SET NULL,
    CONSTRAINT ck_profile_link_policy_type CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_profile_link_policy_intervals CHECK (
        link_deadline > interval '0 seconds'
        AND otp_ttl > interval '0 seconds'
        AND disable_grace_period >= interval '0 seconds'
        AND purge_after > disable_grace_period
    )
);

INSERT INTO profile_link_policies(
    account_type, link_deadline, otp_ttl, max_otp_attempts,
    requires_approval, disable_grace_period, purge_after
) VALUES
    ('CUSTOMER', interval '30 days', interval '10 minutes', 5, false, interval '7 days', interval '90 days'),
    ('HOST', interval '7 days', interval '10 minutes', 5, true, interval '3 days', interval '90 days'),
    ('ADMIN', interval '72 hours', interval '10 minutes', 5, true, interval '24 hours', interval '90 days');

-- Admin profiles may now be created before an Authentication account exists.
ALTER TABLE admin_users ALTER COLUMN auth_account_id DROP NOT NULL;
ALTER TABLE admin_users ALTER COLUMN authorization_subject_id DROP NOT NULL;

-- Preserve all existing account/profile associations as already-linked rows.
INSERT INTO profile_account_links(
    profile_type, profile_id, auth_account_id, status, link_method,
    evidence_verified_at, approved_at, linked_at, reason
)
SELECT 'CUSTOMER', id, auth_account_id, 'LINKED', 'CUSTOMER_SELF_CREATE',
       created_at, created_at, created_at, 'Migrated existing Customer account link'
FROM customers WHERE auth_account_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO profile_account_links(
    profile_type, profile_id, auth_account_id, status, link_method,
    evidence_verified_at, approved_at, linked_at, reason
)
SELECT 'HOST', id, auth_account_id, 'LINKED', 'INVITATION_CCCD_EMAIL_OTP',
       created_at, created_at, created_at, 'Migrated existing Host account link'
FROM hosts WHERE auth_account_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO profile_account_links(
    profile_type, profile_id, auth_account_id, status, link_method,
    evidence_verified_at, approved_at, linked_at, reason
)
SELECT 'ADMIN', id, auth_account_id, 'LINKED', 'INVITATION_CCCD_EMAIL_OTP',
       created_at, created_at, created_at, 'Migrated existing Admin account link'
FROM admin_users WHERE auth_account_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO permissions(resource, action, description)
VALUES
    ('identity-document', 'manage', 'Protect and rotate profile identity documents'),
    ('identity-link', 'read', 'Read profile-account link state'),
    ('identity-link', 'request', 'Request a profile-account link'),
    ('identity-link', 'verify', 'Verify a profile-account link challenge'),
    ('identity-link', 'approve', 'Approve a privileged profile-account link'),
    ('identity-link', 'reject', 'Reject a privileged profile-account link')
ON CONFLICT (resource, action) DO UPDATE
SET description = EXCLUDED.description, active = true, deprecated_at = NULL;

INSERT INTO roles(code, display_name, description, system_role, audience)
VALUES
    ('CUSTOMER_IDENTITY_PENDING', 'Chờ xác minh khách hàng', 'Chỉ được liên kết hồ sơ khách hàng', true, 'CUSTOMER'),
    ('HOST_IDENTITY_PENDING', 'Chờ xác minh chủ nhà', 'Chỉ được liên kết hồ sơ chủ nhà', true, 'HOST'),
    ('ADMIN_IDENTITY_PENDING', 'Chờ xác minh nhân viên', 'Chỉ được liên kết hồ sơ nhân viên', true, 'ADMIN')
ON CONFLICT (code) DO UPDATE
SET display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    system_role = true,
    audience = EXCLUDED.audience,
    active = true;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.code IN ('CUSTOMER_IDENTITY_PENDING', 'HOST_IDENTITY_PENDING', 'ADMIN_IDENTITY_PENDING')
  AND p.code IN ('identity-link:read', 'identity-link:request', 'identity-link:verify')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'SELF', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE r.code IN ('CUSTOMER_IDENTITY_PENDING', 'HOST_IDENTITY_PENDING', 'ADMIN_IDENTITY_PENDING')
  AND p.code IN ('identity-link:read', 'identity-link:request', 'identity-link:verify')
ON CONFLICT DO NOTHING;

-- Existing protected administrator roles receive the management surface.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.audience = 'ADMIN'
  AND r.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')
  AND p.code IN ('identity-document:manage', 'identity-link:read',
                 'identity-link:approve', 'identity-link:reject')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ALL', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE r.audience = 'ADMIN'
  AND r.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')
  AND p.code IN ('identity-document:manage', 'identity-link:read',
                 'identity-link:approve', 'identity-link:reject')
ON CONFLICT DO NOTHING;

COMMENT ON TABLE profile_identity_documents IS
    'User-owned protected CCCD projection. Vault Transit ciphertext and versioned HMAC only; plaintext is forbidden.';
COMMENT ON TABLE profile_account_links IS
    'Audited collision-safe link lifecycle between an Authentication account and one profile of the same type.';
COMMENT ON TABLE profile_link_policies IS
    'Dynamically configurable onboarding expiry, OTP and maker-checker policy per account type.';
