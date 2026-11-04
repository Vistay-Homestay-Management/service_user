SET search_path TO app, extensions, public;

ALTER TABLE permissions ADD COLUMN active boolean NOT NULL DEFAULT true;
ALTER TABLE permissions ADD COLUMN deprecated_at timestamptz;
ALTER TABLE roles ADD COLUMN audience varchar(16) NOT NULL DEFAULT 'ADMIN';
ALTER TABLE roles ADD CONSTRAINT ck_role_audience
    CHECK (audience IN ('CUSTOMER', 'ADMIN', 'HOST'));

CREATE TABLE authorization_subjects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_type varchar(16) NOT NULL,
    auth_account_id uuid NOT NULL,
    active boolean NOT NULL DEFAULT true,
    authorization_version bigint NOT NULL DEFAULT 1 CHECK (authorization_version >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_authorization_subject_type
        CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST')),
    UNIQUE (account_type, auth_account_id)
);

ALTER TABLE customers ADD COLUMN authorization_subject_id uuid
    REFERENCES authorization_subjects(id) ON DELETE RESTRICT;
ALTER TABLE admin_users ADD COLUMN authorization_subject_id uuid
    REFERENCES authorization_subjects(id) ON DELETE RESTRICT;
ALTER TABLE hosts ADD COLUMN authorization_subject_id uuid
    REFERENCES authorization_subjects(id) ON DELETE RESTRICT;

INSERT INTO authorization_subjects(account_type, auth_account_id, active, authorization_version)
SELECT 'CUSTOMER', auth_account_id, profile_status = 'ACTIVE', GREATEST(version, 1)
FROM customers WHERE auth_account_id IS NOT NULL
ON CONFLICT (account_type, auth_account_id) DO NOTHING;

INSERT INTO authorization_subjects(account_type, auth_account_id, active, authorization_version)
SELECT 'ADMIN', auth_account_id, profile_status = 'ACTIVE', GREATEST(version, 1)
FROM admin_users
ON CONFLICT (account_type, auth_account_id) DO NOTHING;

INSERT INTO authorization_subjects(account_type, auth_account_id, active, authorization_version)
SELECT 'HOST', auth_account_id, profile_status = 'ACTIVE', GREATEST(version, 1)
FROM hosts WHERE auth_account_id IS NOT NULL
ON CONFLICT (account_type, auth_account_id) DO NOTHING;

UPDATE customers p SET authorization_subject_id = s.id
FROM authorization_subjects s
WHERE s.account_type = 'CUSTOMER' AND s.auth_account_id = p.auth_account_id;
UPDATE admin_users p SET authorization_subject_id = s.id
FROM authorization_subjects s
WHERE s.account_type = 'ADMIN' AND s.auth_account_id = p.auth_account_id;
UPDATE hosts p SET authorization_subject_id = s.id
FROM authorization_subjects s
WHERE s.account_type = 'HOST' AND s.auth_account_id = p.auth_account_id;

ALTER TABLE admin_users ALTER COLUMN authorization_subject_id SET NOT NULL;
CREATE UNIQUE INDEX ux_customer_authorization_subject ON customers(authorization_subject_id)
    WHERE authorization_subject_id IS NOT NULL;
CREATE UNIQUE INDEX ux_admin_authorization_subject ON admin_users(authorization_subject_id);
CREATE UNIQUE INDEX ux_host_authorization_subject ON hosts(authorization_subject_id)
    WHERE authorization_subject_id IS NOT NULL;

CREATE TABLE role_permission_policies (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    scope_type varchar(24) NOT NULL,
    default_scope boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_role_permission_policy_scope
        CHECK (scope_type IN ('SELF', 'OWN', 'ASSIGNED', 'ALL')),
    PRIMARY KEY (role_id, permission_id, scope_type),
    FOREIGN KEY (role_id, permission_id)
        REFERENCES role_permissions(role_id, permission_id) ON DELETE CASCADE
);

CREATE TABLE subject_role_assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id uuid NOT NULL REFERENCES authorization_subjects(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    assigned_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE SET NULL,
    valid_from timestamptz NOT NULL DEFAULT now(),
    valid_until timestamptz,
    revoked_at timestamptz,
    revoke_reason varchar(500),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_subject_role_dates CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_subject_role_revocation CHECK (revoked_at IS NULL OR revoked_at >= valid_from)
);
CREATE UNIQUE INDEX ux_subject_role_assignment_active
    ON subject_role_assignments(subject_id, role_id) WHERE revoked_at IS NULL;

CREATE TABLE subject_role_permission_scopes (
    assignment_id uuid NOT NULL REFERENCES subject_role_assignments(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
    scope_type varchar(24) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_subject_permission_scope
        CHECK (scope_type IN ('SELF', 'OWN', 'ASSIGNED', 'ALL')),
    PRIMARY KEY (assignment_id, permission_id, scope_type)
);

CREATE TABLE authorization_change_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_subject_id uuid NOT NULL REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    requested_by_subject_id uuid NOT NULL REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    reviewed_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    change_type varchar(32) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'PENDING',
    requested_payload jsonb NOT NULL CHECK (jsonb_typeof(requested_payload) = 'object'),
    reason varchar(500) NOT NULL,
    review_reason varchar(500),
    expected_authorization_version bigint NOT NULL,
    idempotency_key varchar(160) NOT NULL,
    expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours',
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_authorization_change_type
        CHECK (change_type IN ('GRANT_ROLE', 'EXPAND_SCOPES')),
    CONSTRAINT ck_authorization_change_status
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'STALE')),
    CONSTRAINT ck_authorization_change_reason CHECK (length(trim(reason)) >= 8),
    UNIQUE (requested_by_subject_id, idempotency_key)
);
CREATE INDEX ix_authorization_change_pending
    ON authorization_change_requests(status, expires_at, created_at);

CREATE TABLE authorization_audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE SET NULL,
    target_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE SET NULL,
    action varchar(100) NOT NULL,
    before_state jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(before_state) = 'object'),
    after_state jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(after_state) = 'object'),
    reason varchar(500) NOT NULL,
    correlation_id varchar(100),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_authorization_audit_target
    ON authorization_audit_events(target_subject_id, created_at DESC);

CREATE TABLE authorization_bootstrap_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    first_super_admin_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    second_approver_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    exception_consumed_at timestamptz,
    CHECK ((exception_consumed_at IS NULL AND second_approver_subject_id IS NULL)
        OR (exception_consumed_at IS NOT NULL AND second_approver_subject_id IS NOT NULL))
);
INSERT INTO authorization_bootstrap_state(singleton, first_super_admin_subject_id)
VALUES (true, (SELECT authorization_subject_id FROM admin_users ORDER BY created_at LIMIT 1));

INSERT INTO roles(code, display_name, description, system_role, audience) VALUES
    ('SECURITY_ADMIN', 'Quản trị bảo mật', 'Quản lý tài khoản và phê duyệt quyền', true, 'ADMIN'),
    ('ACCOUNT_ADMIN', 'Quản trị tài khoản', 'Quản lý vòng đời tài khoản và hồ sơ', true, 'ADMIN'),
    ('FINANCE_OPERATOR', 'Vận hành tài chính', 'Xử lý thanh toán và đối soát', true, 'ADMIN'),
    ('FINANCE_APPROVER', 'Phê duyệt tài chính', 'Phê duyệt hoàn tiền và quyết toán', true, 'ADMIN'),
    ('AUDITOR', 'Kiểm toán', 'Quyền đọc và xuất báo cáo kiểm toán', true, 'ADMIN'),
    ('CUSTOMER_MEMBER', 'Khách hàng', 'Quyền tự phục vụ khách hàng', true, 'CUSTOMER'),
    ('HOST_PARTNER', 'Đối tác chủ nhà', 'Quyền quản lý dữ liệu thuộc chủ nhà', true, 'HOST')
ON CONFLICT (code) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    system_role = true,
    audience = EXCLUDED.audience,
    active = true;

INSERT INTO permissions(resource, action, description) VALUES
    ('profile','read','Xem hồ sơ'), ('profile','update','Cập nhật hồ sơ'),
    ('account','read','Xem tài khoản'), ('account','provision','Tạo tài khoản'),
    ('account','activate','Kích hoạt tài khoản'), ('account','suspend','Khóa tài khoản'),
    ('account','unlock','Mở khóa tài khoản'), ('account','revoke_session','Thu hồi phiên'),
    ('authorization','read','Xem phân quyền'), ('authorization','grant','Yêu cầu tăng quyền'),
    ('authorization','approve','Phê duyệt tăng quyền'), ('authorization','revoke','Thu hồi quyền'),
    ('audit','read','Xem audit'), ('audit','export','Xuất audit'),
    ('customer','read_sensitive','Xem dữ liệu khách nhạy cảm'), ('customer','update','Cập nhật khách'),
    ('host','read','Xem chủ nhà'), ('host','update','Cập nhật chủ nhà'), ('host','verify','Xác minh chủ nhà'),
    ('booking','read_sensitive','Xem dữ liệu booking nhạy cảm'), ('booking','assign','Giao booking'),
    ('booking','check_in','Check-in'), ('booking','check_out','Check-out'),
    ('property','create','Tạo căn hộ'), ('property','update','Cập nhật căn hộ'),
    ('property','approve','Phê duyệt căn hộ'), ('property','publish','Đăng căn hộ'),
    ('contract','read','Xem hợp đồng'), ('contract','create','Tạo hợp đồng'),
    ('contract','update','Cập nhật hợp đồng'), ('contract','accept','Chấp nhận hợp đồng'),
    ('contract','approve','Phê duyệt hợp đồng'), ('contract','terminate','Chấm dứt hợp đồng'),
    ('pricing','read','Xem giá'), ('pricing','update','Cập nhật giá'), ('pricing','approve','Phê duyệt giá'),
    ('inventory','read','Xem tồn phòng'), ('inventory','update','Cập nhật tồn phòng'), ('inventory','block','Khóa tồn phòng'),
    ('media','read','Xem media'), ('media','upload','Tải media lên'), ('media','delete','Xóa media'),
    ('operations','create','Tạo công việc'), ('operations','update','Cập nhật công việc'),
    ('operations','assign','Giao công việc'), ('operations','close','Đóng công việc'),
    ('finance','export','Xuất dữ liệu tài chính'),
    ('payment','read','Xem thanh toán'), ('payment','create','Tạo thanh toán'),
    ('payment','cancel','Hủy thanh toán'), ('payment','reconcile','Đối soát thanh toán'),
    ('refund','read','Xem hoàn tiền'), ('refund','request','Yêu cầu hoàn tiền'), ('refund','approve','Phê duyệt hoàn tiền'),
    ('settlement','read','Xem quyết toán'), ('settlement','approve','Phê duyệt quyết toán'), ('settlement','export','Xuất quyết toán'),
    ('report','export','Xuất báo cáo'),
    ('notification','read','Xem thông báo'), ('notification','update','Cập nhật thông báo'), ('notification','send','Gửi thông báo')
ON CONFLICT (resource, action) DO UPDATE SET description = EXCLUDED.description, active = true, deprecated_at = NULL;

UPDATE permissions SET active = false, deprecated_at = now()
WHERE code IN ('user:manage','property:manage','finance:manage','operations:manage','finance:refund');

-- SUPER_ADMIN is the only legacy role with effective permissions. It receives every active permission at ALL.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.code = 'SUPER_ADMIN' AND p.active
ON CONFLICT DO NOTHING;
INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT r.id, p.id, 'ALL', true FROM roles r CROSS JOIN permissions p
WHERE r.code = 'SUPER_ADMIN' AND p.active
ON CONFLICT DO NOTHING;

INSERT INTO subject_role_assignments(
    id, subject_id, role_id, assigned_by_subject_id, valid_from, valid_until, revoked_at, revoke_reason, created_at
)
SELECT aur.id, au.authorization_subject_id, aur.role_id, assigner.authorization_subject_id,
       aur.valid_from, aur.valid_until, aur.revoked_at, aur.revoke_reason, aur.created_at
FROM admin_user_roles aur
JOIN admin_users au ON au.id = aur.admin_user_id
LEFT JOIN admin_users assigner ON assigner.id = aur.assigned_by_admin_user_id
ON CONFLICT (id) DO NOTHING;

INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT sra.id, rp.permission_id, 'ALL'
FROM subject_role_assignments sra
JOIN roles r ON r.id = sra.role_id AND r.code = 'SUPER_ADMIN'
JOIN role_permissions rp ON rp.role_id = r.id
ON CONFLICT DO NOTHING;

-- Fixed role templates. No wildcard permission is stored; the LIKE clauses expand the checked-in catalog.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.active
WHERE (r.code = 'SECURITY_ADMIN' AND (p.resource IN ('account','authorization','audit') OR p.code = 'profile:read'))
   OR (r.code = 'ACCOUNT_ADMIN' AND (p.resource IN ('account','profile','host') OR p.code IN ('customer:read','customer:read_sensitive','customer:update','authorization:read')))
   OR (r.code = 'MANAGER' AND p.resource IN ('customer','booking','property','contract','pricing','inventory','media','operations','report','notification'))
   OR (r.code = 'RECEPTIONIST' AND p.code IN ('customer:read','customer:read_sensitive','customer:update','booking:read','booking:read_sensitive','booking:create','booking:update','booking:cancel','booking:check_in','booking:check_out','property:read','pricing:read','inventory:read','inventory:update','operations:read','operations:create','operations:update'))
   OR (r.code = 'STAFF' AND p.code IN ('customer:read','customer:read_sensitive','booking:read','booking:update','booking:check_in','booking:check_out','property:read','inventory:read','operations:read','operations:update','operations:close'))
   OR (r.code = 'CTV' AND p.code IN ('customer:read','booking:read','booking:create','booking:update','property:read','pricing:read','inventory:read','report:read'))
   OR (r.code = 'FINANCE_OPERATOR' AND (p.resource IN ('finance','payment','settlement') OR p.code IN ('refund:read','refund:request','booking:read','booking:read_sensitive')))
   OR (r.code = 'FINANCE_APPROVER' AND p.code IN ('finance:read','finance:export','payment:read','refund:read','refund:approve','settlement:read','settlement:approve','settlement:export','booking:read','booking:read_sensitive'))
   OR (r.code = 'AUDITOR' AND ((p.resource IN ('audit','finance','report')) OR p.code IN ('payment:read','refund:read','settlement:read')))
   OR (r.code = 'CUSTOMER_MEMBER' AND p.code IN ('profile:read','profile:update','notification:read','notification:update','booking:read','booking:create','booking:update','booking:cancel','payment:read','payment:create','refund:read','refund:request','media:read','media:upload','media:delete'))
   OR (r.code = 'HOST_PARTNER' AND p.code IN ('profile:read','profile:update','notification:read','notification:update','property:read','property:update','contract:read','contract:accept','booking:read','pricing:read','pricing:update','inventory:read','inventory:update','operations:read','operations:create','operations:update','settlement:read','report:read','report:export','media:read','media:upload','media:delete'))
ON CONFLICT DO NOTHING;

-- Global administration roles always use ALL.
INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ALL', true
FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
WHERE r.code IN ('SECURITY_ADMIN','ACCOUNT_ADMIN','FINANCE_APPROVER','AUDITOR')
ON CONFLICT DO NOTHING;

-- Business roles default to ASSIGNED and may be explicitly elevated to ALL.
INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, scope.scope_type, scope.scope_type = 'ASSIGNED'
FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
CROSS JOIN (VALUES ('ASSIGNED'), ('ALL')) AS scope(scope_type)
WHERE r.code IN ('MANAGER','STAFF','FINANCE_OPERATOR')
ON CONFLICT DO NOTHING;

-- RECEPTIONIST and CTV may use own or assigned records; catalog data needed for sales is read globally.
INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id,
       CASE WHEN p.code IN ('property:read','pricing:read','inventory:read') THEN 'ALL' ELSE scope.scope_type END,
       CASE WHEN p.code IN ('property:read','pricing:read','inventory:read') THEN true ELSE scope.scope_type = 'ASSIGNED' END
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
JOIN permissions p ON p.id = rp.permission_id
CROSS JOIN (VALUES ('OWN'), ('ASSIGNED')) AS scope(scope_type)
WHERE r.code IN ('RECEPTIONIST','CTV')
ON CONFLICT DO NOTHING;

-- Customer self-service separates profile SELF from owned domain records.
INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id,
       CASE WHEN p.resource IN ('profile','notification') THEN 'SELF' ELSE 'OWN' END, true
FROM role_permissions rp JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE r.code = 'CUSTOMER_MEMBER'
ON CONFLICT DO NOTHING;

-- Host profile is SELF; all partner domain relations are evaluated as OWN by their owning service.
INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id,
       CASE WHEN p.resource IN ('profile','notification') THEN 'SELF' ELSE 'OWN' END, true
FROM role_permissions rp JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE r.code = 'HOST_PARTNER'
ON CONFLICT DO NOTHING;

-- Preserve the existing installation as a completed first-admin bootstrap, but leave the second approver exception unused.
UPDATE authorization_bootstrap_state SET first_super_admin_subject_id = candidate.subject_id
FROM (
    SELECT sra.subject_id FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    WHERE r.code = 'SUPER_ADMIN' AND sra.revoked_at IS NULL
    ORDER BY sra.created_at LIMIT 1
) candidate
WHERE authorization_bootstrap_state.first_super_admin_subject_id IS NULL;
