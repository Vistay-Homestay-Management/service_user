SET search_path TO app, extensions, public;

ALTER TABLE profile_link_policies
    ADD COLUMN registration_enabled boolean NOT NULL DEFAULT true;

UPDATE profile_link_policies
SET registration_enabled = account_type <> 'ADMIN';

CREATE TABLE profile_creation_requests (
    idempotency_key varchar(160) PRIMARY KEY,
    request_hash char(64) NOT NULL,
    profile_type varchar(16) NOT NULL,
    profile_id uuid NOT NULL,
    actor_account_id uuid NOT NULL,
    reason varchar(500) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_profile_creation_type CHECK (profile_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_profile_creation_reason CHECK (char_length(reason) BETWEEN 8 AND 500)
);

CREATE TABLE identity_policy_change_requests (
    idempotency_key varchar(160) PRIMARY KEY,
    request_hash char(64) NOT NULL,
    account_type varchar(16) NOT NULL,
    resulting_policy_version bigint NOT NULL CHECK (resulting_policy_version > 0),
    actor_account_id uuid NOT NULL,
    reason varchar(500) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_identity_policy_change_type CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    CONSTRAINT ck_identity_policy_change_reason CHECK (char_length(reason) BETWEEN 8 AND 500)
);

INSERT INTO permissions(resource, action, description) VALUES
    ('customer-profile', 'create', 'Tạo hồ sơ khách hàng chưa cần tài khoản'),
    ('admin-profile', 'create', 'Tạo hồ sơ nhân viên chưa cần tài khoản'),
    ('host-profile', 'create', 'Tạo hồ sơ chủ nhà chưa cần tài khoản'),
    ('customer-account', 'provision', 'Tạo hoặc gửi lời mời tài khoản khách hàng'),
    ('host-account', 'provision', 'Tạo hoặc gửi lời mời tài khoản chủ nhà'),
    ('admin-account', 'provision', 'Tạo hoặc gửi lời mời tài khoản nhân viên'),
    ('identity-policy', 'read', 'Xem chính sách đăng ký và liên kết hồ sơ'),
    ('identity-policy', 'update', 'Cập nhật chính sách đăng ký và liên kết hồ sơ')
ON CONFLICT (resource, action) DO UPDATE SET
    description = EXCLUDED.description,
    active = true,
    deprecated_at = NULL;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.audience = 'ADMIN'
  AND r.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')
  AND p.code IN (
      'customer-profile:create', 'admin-profile:create', 'host-profile:create',
      'customer-account:provision', 'host-account:provision', 'admin-account:provision',
      'identity-policy:read', 'identity-policy:update'
  )
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ALL', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE r.audience = 'ADMIN'
  AND r.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')
  AND p.code IN (
      'customer-profile:create', 'admin-profile:create', 'host-profile:create',
      'customer-account:provision', 'host-account:provision', 'admin-account:provision',
      'identity-policy:read', 'identity-policy:update'
  )
ON CONFLICT DO NOTHING;

UPDATE authorization_catalog_state
SET catalog_version = catalog_version + 1, updated_at = now()
WHERE singleton;

COMMENT ON COLUMN profile_link_policies.registration_enabled IS
    'User-owned source of truth for public registration. Authentication projects this value to the matching Keycloak realm.';
COMMENT ON TABLE profile_creation_requests IS
    'Replay-safe administrative creation of account-independent Customer, Admin and Host profiles.';
