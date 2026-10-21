SET search_path TO app, extensions, public;

-- auth_account_id is an external reference to Authentication Service.
CREATE TABLE customers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_account_id uuid UNIQUE,
    full_name varchar(180) NOT NULL,
    email citext,
    normalized_phone varchar(32),
    date_of_birth date,
    nationality_code char(3),
    avatar_media_id uuid,
    address varchar(500),
    notes varchar(2000),
    profile_status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_customer_profile_status CHECK (profile_status IN ('ACTIVE', 'INACTIVE', 'ANONYMIZED'))
);
CREATE INDEX ix_customer_phone ON customers(normalized_phone) WHERE normalized_phone IS NOT NULL;
CREATE INDEX ix_customer_email ON customers(email) WHERE email IS NOT NULL;

CREATE TABLE admin_users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_account_id uuid NOT NULL UNIQUE,
    employee_code varchar(40) UNIQUE,
    full_name varchar(180) NOT NULL,
    email citext,
    normalized_phone varchar(32),
    user_type varchar(24) NOT NULL,
    branch_reference_id uuid,
    avatar_media_id uuid,
    profile_status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    hired_on date,
    ended_on date,
    version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_admin_user_type CHECK (user_type IN ('STAFF', 'RECEPTIONIST', 'CTV', 'MANAGER', 'ADMIN')),
    CONSTRAINT ck_admin_user_status CHECK (profile_status IN ('ACTIVE', 'INACTIVE', 'SUSPENDED')),
    CONSTRAINT ck_admin_user_employment_dates CHECK (ended_on IS NULL OR hired_on IS NULL OR ended_on >= hired_on)
);
CREATE INDEX ix_admin_user_branch ON admin_users(branch_reference_id, profile_status);

CREATE TABLE hosts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_account_id uuid UNIQUE,
    host_code varchar(40) UNIQUE,
    full_name varchar(180) NOT NULL,
    email citext,
    normalized_phone varchar(32),
    avatar_media_id uuid,
    address varchar(500),
    tax_code varchar(40),
    profile_status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    verification_status varchar(24) NOT NULL DEFAULT 'UNVERIFIED',
    version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_host_profile_status CHECK (profile_status IN ('ACTIVE', 'INACTIVE', 'SUSPENDED')),
    CONSTRAINT ck_host_verification_status CHECK (verification_status IN ('UNVERIFIED', 'PENDING', 'VERIFIED', 'REJECTED'))
);
CREATE INDEX ix_host_phone ON hosts(normalized_phone) WHERE normalized_phone IS NOT NULL;
CREATE INDEX ix_host_email ON hosts(email) WHERE email IS NOT NULL;

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code varchar(64) NOT NULL UNIQUE,
    display_name varchar(120) NOT NULL,
    description varchar(500),
    system_role boolean NOT NULL DEFAULT false,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource varchar(80) NOT NULL,
    action varchar(40) NOT NULL,
    code varchar(121) GENERATED ALWAYS AS (resource || ':' || action) STORED,
    description varchar(500),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (resource, action),
    UNIQUE (code),
    CONSTRAINT ck_permission_resource CHECK (resource ~ '^[a-z][a-z0-9_-]*$'),
    CONSTRAINT ck_permission_action CHECK (action ~ '^[a-z][a-z0-9_-]*$')
);

CREATE TABLE role_permissions (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE admin_user_roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_user_id uuid NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by_admin_user_id uuid REFERENCES admin_users(id) ON DELETE SET NULL,
    valid_from timestamptz NOT NULL DEFAULT now(),
    valid_until timestamptz,
    revoked_at timestamptz,
    revoke_reason varchar(500),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_admin_user_role_dates CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_admin_user_role_revocation CHECK (revoked_at IS NULL OR revoked_at >= valid_from)
);
CREATE UNIQUE INDEX ux_admin_user_role_active ON admin_user_roles(admin_user_id, role_id) WHERE revoked_at IS NULL;

-- ALL has no reference ID. BRANCH/ASSIGNED references an ID owned by the
-- appropriate domain; OWN is evaluated from the authenticated user.
CREATE TABLE admin_user_role_scopes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_user_role_id uuid NOT NULL REFERENCES admin_user_roles(id) ON DELETE CASCADE,
    scope_type varchar(24) NOT NULL,
    scope_reference_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_role_scope_type CHECK (scope_type IN ('OWN', 'ASSIGNED', 'BRANCH', 'ALL')),
    CONSTRAINT ck_role_scope_reference CHECK (
        (scope_type IN ('OWN', 'ALL') AND scope_reference_id IS NULL)
        OR (scope_type IN ('ASSIGNED', 'BRANCH') AND scope_reference_id IS NOT NULL)
    ),
    UNIQUE NULLS NOT DISTINCT (admin_user_role_id, scope_type, scope_reference_id)
);

INSERT INTO roles(code, display_name, description, system_role) VALUES
    ('SUPER_ADMIN', 'Quản trị toàn hệ thống', 'Toàn quyền trong phạm vi tổ chức', true),
    ('MANAGER', 'Quản lý', 'Quản lý nghiệp vụ và phạm vi được giao', true),
    ('STAFF', 'Nhân viên', 'Xử lý nghiệp vụ theo phân công', true),
    ('RECEPTIONIST', 'Lễ tân', 'Quản lý khách và booking theo phạm vi', true),
    ('CTV', 'Cộng tác viên', 'Tạo và theo dõi booking được giao', true)
ON CONFLICT (code) DO NOTHING;

INSERT INTO permissions(resource, action, description) VALUES
    ('booking', 'read', 'Xem booking'),
    ('booking', 'create', 'Tạo booking'),
    ('booking', 'update', 'Cập nhật booking'),
    ('booking', 'cancel', 'Hủy booking'),
    ('property', 'read', 'Xem căn hộ'),
    ('property', 'manage', 'Quản lý căn hộ và hợp đồng'),
    ('customer', 'read', 'Xem hồ sơ khách'),
    ('customer', 'manage', 'Quản lý hồ sơ khách'),
    ('finance', 'read', 'Xem dữ liệu tài chính'),
    ('finance', 'manage', 'Quản lý dữ liệu tài chính'),
    ('finance', 'refund', 'Phê duyệt hoặc thực hiện hoàn tiền'),
    ('operations', 'read', 'Xem dữ liệu vận hành'),
    ('operations', 'manage', 'Quản lý sự cố và công việc'),
    ('user', 'manage', 'Quản lý hồ sơ, role và permission'),
    ('report', 'read', 'Xem báo cáo')
ON CONFLICT (resource, action) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p WHERE r.code = 'SUPER_ADMIN'
ON CONFLICT DO NOTHING;

CREATE TABLE audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_admin_user_id uuid,
    action varchar(100) NOT NULL,
    aggregate_type varchar(100) NOT NULL,
    aggregate_id uuid NOT NULL,
    changes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(changes) = 'object'),
    correlation_id varchar(100),
    ip_address inet,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_user_audit_aggregate ON audit_events(aggregate_type, aggregate_id, created_at DESC);

CREATE TABLE processed_events (
    event_id uuid NOT NULL,
    consumer_name varchar(120) NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, consumer_name)
);

CREATE TABLE outbox_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type varchar(100) NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version >= 0),
    event_type varchar(160) NOT NULL,
    event_version integer NOT NULL DEFAULT 1 CHECK (event_version > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    available_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0),
    last_error text,
    correlation_id varchar(100),
    causation_id varchar(100)
);
CREATE INDEX ix_user_outbox_pending ON outbox_events(available_at, occurred_at) WHERE published_at IS NULL;
