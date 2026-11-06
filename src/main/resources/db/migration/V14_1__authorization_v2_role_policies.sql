SET search_path TO app, extensions, public;

ALTER TABLE roles ADD COLUMN policy_version bigint NOT NULL DEFAULT 1
    CHECK (policy_version >= 1);
ALTER TABLE roles ADD COLUMN deactivated_at timestamptz;

CREATE TABLE authorization_catalog_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    catalog_version bigint NOT NULL DEFAULT 1 CHECK (catalog_version >= 1),
    schema_version integer NOT NULL DEFAULT 2 CHECK (schema_version = 2),
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO authorization_catalog_state(singleton) VALUES (true);

CREATE TABLE permission_aliases (
    alias_code varchar(121) PRIMARY KEY,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_permission_alias_code
        CHECK (alias_code ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9_-]*$')
);

CREATE TABLE role_permission_partition_types (
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    partition_type varchar(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_role_policy_partition_type
        CHECK (partition_type ~ '^[A-Z][A-Z0-9_]{1,63}$'),
    PRIMARY KEY (role_id, permission_id, partition_type),
    FOREIGN KEY (role_id, permission_id)
        REFERENCES role_permissions(role_id, permission_id) ON DELETE CASCADE
);

CREATE TABLE role_policy_change_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_role_id uuid REFERENCES roles(id) ON DELETE RESTRICT,
    target_role_code varchar(64) NOT NULL,
    requested_by_subject_id uuid NOT NULL REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    reviewed_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    change_type varchar(32) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'PENDING',
    requested_payload jsonb NOT NULL CHECK (jsonb_typeof(requested_payload) = 'object'),
    request_hash char(64) NOT NULL,
    expected_role_version bigint,
    reason varchar(500) NOT NULL,
    review_reason varchar(500),
    idempotency_key varchar(160) NOT NULL,
    expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours',
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_role_policy_change_type
        CHECK (change_type IN ('CREATE_ROLE', 'CHANGE_PERMISSIONS', 'DEACTIVATE_ROLE')),
    CONSTRAINT ck_role_policy_change_status
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'STALE')),
    CONSTRAINT ck_role_policy_change_reason CHECK (length(trim(reason)) >= 8),
    CONSTRAINT ck_role_policy_change_target CHECK (
        (change_type = 'CREATE_ROLE' AND expected_role_version IS NULL)
        OR (change_type <> 'CREATE_ROLE' AND target_role_id IS NOT NULL AND expected_role_version IS NOT NULL)
    ),
    UNIQUE (requested_by_subject_id, idempotency_key)
);
CREATE INDEX ix_role_policy_change_pending
    ON role_policy_change_requests(status, expires_at, created_at);

CREATE OR REPLACE FUNCTION protect_system_role_identity() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.system_role THEN
        RAISE EXCEPTION 'system roles cannot be deleted';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.system_role AND (
        NEW.code IS DISTINCT FROM OLD.code
        OR NEW.audience IS DISTINCT FROM OLD.audience
        OR NEW.system_role IS DISTINCT FROM OLD.system_role
        OR NEW.active IS DISTINCT FROM OLD.active
    ) THEN
        RAISE EXCEPTION 'system role identity and lifecycle are immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_protect_system_role_identity
BEFORE UPDATE OR DELETE ON roles
FOR EACH ROW EXECUTE FUNCTION protect_system_role_identity();

INSERT INTO permissions(resource, action, description) VALUES
    ('role', 'read', 'Xem danh mục role và policy'),
    ('role', 'change-request', 'Đề xuất tạo, sửa hoặc vô hiệu hóa role'),
    ('role', 'change-approve', 'Phê duyệt thay đổi role-policy'),
    ('booking-sensitive', 'read', 'Xem dữ liệu booking thương mại hoặc nhạy cảm'),
    ('notification-template', 'read', 'Xem notification template'),
    ('notification-template', 'manage', 'Quản lý notification template'),
    ('notification-template', 'publish', 'Phát hành notification template'),
    ('notification-delivery', 'read', 'Xem trạng thái delivery'),
    ('notification-delivery', 'retry', 'Retry notification delivery'),
    ('notification-recipient-exception', 'read', 'Xem lỗi phân giải notification recipient'),
    ('notification-recipient-exception', 'repair', 'Sửa lỗi phân giải notification recipient'),
    ('pricing', 'publish', 'Phát hành chính sách giá'),
    ('pricing', 'override', 'Ghi đè giá theo thẩm quyền')
ON CONFLICT (resource, action) DO UPDATE SET
    description = EXCLUDED.description, active = true, deprecated_at = NULL;

INSERT INTO permission_aliases(alias_code, permission_id)
SELECT alias.alias_code, canonical.id
FROM (VALUES
    ('booking:read_sensitive', 'booking-sensitive:read'),
    ('notifications:read', 'notification:read'),
    ('notifications:update', 'notification:update')
) AS alias(alias_code, canonical_code)
JOIN permissions canonical ON canonical.code = alias.canonical_code
ON CONFLICT (alias_code) DO UPDATE SET permission_id = EXCLUDED.permission_id;

-- Preserve existing booking-sensitive grants while clients move to the
-- canonical two-part kebab-case permission code.
INSERT INTO role_permissions(role_id, permission_id)
SELECT rp.role_id, canonical.id
FROM role_permissions rp
JOIN permissions legacy ON legacy.id = rp.permission_id
JOIN permissions canonical ON canonical.code = 'booking-sensitive:read'
WHERE legacy.code = 'booking:read_sensitive'
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT policy.role_id, canonical.id, policy.scope_type, policy.default_scope
FROM role_permission_policies policy
JOIN permissions legacy ON legacy.id = policy.permission_id
JOIN permissions canonical ON canonical.code = 'booking-sensitive:read'
WHERE legacy.code = 'booking:read_sensitive'
ON CONFLICT DO NOTHING;

INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT legacy_scope.assignment_id, canonical.id, legacy_scope.scope_type
FROM subject_role_permission_scopes legacy_scope
JOIN permissions legacy ON legacy.id = legacy_scope.permission_id
JOIN permissions canonical ON canonical.code = 'booking-sensitive:read'
WHERE legacy.code = 'booking:read_sensitive'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT rp.role_id, canonical.id
FROM role_permissions rp
JOIN permissions legacy ON legacy.id = rp.permission_id
JOIN permissions canonical ON canonical.code = 'pricing:publish'
WHERE legacy.code = 'pricing:approve'
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT policy.role_id, canonical.id, policy.scope_type, policy.default_scope
FROM role_permission_policies policy
JOIN permissions legacy ON legacy.id = policy.permission_id
JOIN permissions canonical ON canonical.code = 'pricing:publish'
WHERE legacy.code = 'pricing:approve'
ON CONFLICT DO NOTHING;

INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT legacy_scope.assignment_id, canonical.id, legacy_scope.scope_type
FROM subject_role_permission_scopes legacy_scope
JOIN permissions legacy ON legacy.id = legacy_scope.permission_id
JOIN permissions canonical ON canonical.code = 'pricing:publish'
WHERE legacy.code = 'pricing:approve'
ON CONFLICT DO NOTHING;

-- Security administrators own the maker-checker workspace. SUPER_ADMIN keeps
-- the break-glass path but cannot approve its own request.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')
  AND p.code IN ('role:read', 'role:change-request', 'role:change-approve')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT r.id, p.id, 'ALL', true
FROM roles r CROSS JOIN permissions p
WHERE r.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')
  AND p.code IN ('role:read', 'role:change-request', 'role:change-approve')
ON CONFLICT DO NOTHING;

-- Existing assignments are a compatibility projection only. New runtime
-- decisions read role policy and domain-owned subject partitions.
INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT sra.id, rp.permission_id, rpp.scope_type
FROM subject_role_assignments sra
JOIN role_permissions rp ON rp.role_id = sra.role_id
JOIN role_permission_policies rpp
  ON rpp.role_id = rp.role_id AND rpp.permission_id = rp.permission_id
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code IN ('role:read', 'role:change-request', 'role:change-approve')
ON CONFLICT DO NOTHING;
