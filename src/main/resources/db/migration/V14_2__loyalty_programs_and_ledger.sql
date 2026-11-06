SET search_path TO app, extensions, public;

CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA extensions;

INSERT INTO permissions(resource, action, description) VALUES
    ('loyalty-program', 'read', 'Read loyalty program policy and versions'),
    ('loyalty-program', 'change-request', 'Request loyalty program changes'),
    ('loyalty-program', 'change-approve', 'Approve loyalty program changes'),
    ('loyalty-profile', 'read', 'Read a qualifying-points tier profile'),
    ('loyalty-point', 'adjust', 'Append an audited qualifying-points adjustment'),
    ('property-attribute', 'read', 'Read property attribute definitions'),
    ('property-attribute', 'manage', 'Manage property attribute drafts and values'),
    ('property-attribute', 'publish', 'Publish property attribute definitions'),
    ('booking-policy', 'read', 'Read booking policy versions'),
    ('booking-policy', 'change-request', 'Request booking policy changes'),
    ('booking-policy', 'change-approve', 'Approve booking policy changes'),
    ('booking-policy', 'simulate', 'Simulate booking policy decisions')
ON CONFLICT (resource, action) DO UPDATE SET
    description = EXCLUDED.description, active = true, deprecated_at = NULL;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.code = 'SUPER_ADMIN'
  AND p.code IN (
    'loyalty-program:read', 'loyalty-program:change-request',
    'loyalty-program:change-approve', 'loyalty-profile:read',
    'loyalty-point:adjust', 'property-attribute:read',
    'property-attribute:manage', 'property-attribute:publish',
    'booking-policy:read', 'booking-policy:change-request',
    'booking-policy:change-approve', 'booking-policy:simulate'
  )
ON CONFLICT DO NOTHING;

INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT assignment.id, permission.id,
       CASE WHEN role.code = 'CUSTOMER_MEMBER' THEN 'SELF' ELSE 'OWN' END
FROM subject_role_assignments assignment
JOIN roles role ON role.id = assignment.role_id
JOIN permissions permission
  ON (role.code = 'CUSTOMER_MEMBER' AND permission.code = 'loyalty-profile:read')
  OR (role.code = 'HOST_PARTNER' AND permission.code IN ('property-attribute:read', 'property-attribute:manage'))
WHERE assignment.revoked_at IS NULL
  AND assignment.valid_from <= now()
  AND (assignment.valid_until IS NULL OR assignment.valid_until > now())
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT r.id, p.id, 'ALL', true
FROM roles r CROSS JOIN permissions p
WHERE r.code = 'SUPER_ADMIN'
  AND p.code IN (
    'loyalty-program:read', 'loyalty-program:change-request',
    'loyalty-program:change-approve', 'loyalty-profile:read',
    'loyalty-point:adjust', 'property-attribute:read',
    'property-attribute:manage', 'property-attribute:publish',
    'booking-policy:read', 'booking-policy:change-request',
    'booking-policy:change-approve', 'booking-policy:simulate'
  )
ON CONFLICT DO NOTHING;

-- Self-service/host defaults remain least-privilege; broader administration
-- is assigned through dynamic custom roles rather than hard-coded templates.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p
  ON (r.code = 'CUSTOMER_MEMBER' AND p.code = 'loyalty-profile:read')
  OR (r.code = 'HOST_PARTNER' AND p.code IN ('property-attribute:read', 'property-attribute:manage'))
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT r.id, p.id, CASE WHEN r.code = 'CUSTOMER_MEMBER' THEN 'SELF' ELSE 'OWN' END, true
FROM roles r JOIN permissions p
  ON (r.code = 'CUSTOMER_MEMBER' AND p.code = 'loyalty-profile:read')
  OR (r.code = 'HOST_PARTNER' AND p.code IN ('property-attribute:read', 'property-attribute:manage'))
ON CONFLICT DO NOTHING;

CREATE TABLE loyalty_programs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code varchar(64) NOT NULL UNIQUE,
    name varchar(160) NOT NULL,
    scope_type varchar(24) NOT NULL DEFAULT 'GLOBAL',
    scope_id uuid,
    active boolean NOT NULL DEFAULT true,
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_loyalty_program_code CHECK (code ~ '^[a-z][a-z0-9-]{1,63}$'),
    CONSTRAINT ck_loyalty_program_scope CHECK (
      (scope_type = 'GLOBAL' AND scope_id IS NULL)
      OR (scope_type = 'ORGANIZATION' AND scope_id IS NOT NULL)
    )
);

CREATE TABLE loyalty_program_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id uuid NOT NULL REFERENCES loyalty_programs(id) ON DELETE RESTRICT,
    version integer NOT NULL CHECK (version > 0),
    status varchar(24) NOT NULL,
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    qualification_window varchar(24) NOT NULL DEFAULT 'LIFETIME',
    rolling_window_days integer,
    effective_from timestamptz NOT NULL,
    effective_to timestamptz,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    fingerprint char(64) NOT NULL,
    requested_by_subject_id uuid NOT NULL REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    approved_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    reason varchar(500) NOT NULL,
    approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_loyalty_program_version_status CHECK (
      status IN ('PENDING_APPROVAL', 'SCHEDULED', 'ACTIVE', 'SUPERSEDED', 'REJECTED', 'RETIRED')
    ),
    CONSTRAINT ck_loyalty_program_window CHECK (
      (qualification_window = 'LIFETIME' AND rolling_window_days IS NULL)
      OR (qualification_window = 'ROLLING_DAYS' AND rolling_window_days BETWEEN 30 AND 3650)
    ),
    CONSTRAINT ck_loyalty_program_effective CHECK (effective_to IS NULL OR effective_to > effective_from),
    CONSTRAINT ck_loyalty_program_checker CHECK (
      approved_by_subject_id IS NULL OR approved_by_subject_id <> requested_by_subject_id
    ),
    UNIQUE (program_id, version),
    UNIQUE (fingerprint)
);
CREATE INDEX ix_loyalty_program_effective
  ON loyalty_program_versions(program_id, status, effective_from, effective_to);

ALTER TABLE loyalty_program_versions ADD CONSTRAINT ex_loyalty_program_active_overlap
EXCLUDE USING gist (
  program_id WITH =,
  tstzrange(effective_from, COALESCE(effective_to, 'infinity'::timestamptz), '[)') WITH &&
) WHERE (status IN ('SCHEDULED', 'ACTIVE'));

CREATE TABLE loyalty_tier_bands (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    program_version_id uuid NOT NULL REFERENCES loyalty_program_versions(id) ON DELETE CASCADE,
    code varchar(64) NOT NULL,
    display_name varchar(120) NOT NULL,
    minimum_points bigint NOT NULL CHECK (minimum_points >= 0),
    display_order integer NOT NULL CHECK (display_order >= 0),
    presentation jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(presentation) = 'object'),
    UNIQUE (program_version_id, code),
    UNIQUE (program_version_id, minimum_points),
    UNIQUE (program_version_id, display_order),
    CONSTRAINT ck_loyalty_tier_code CHECK (code ~ '^[a-z][a-z0-9-]{1,63}$')
);

CREATE TABLE loyalty_earning_rules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    program_version_id uuid NOT NULL REFERENCES loyalty_program_versions(id) ON DELETE CASCADE,
    code varchar(64) NOT NULL,
    rule_type varchar(32) NOT NULL,
    points bigint NOT NULL CHECK (points > 0),
    amount_block numeric(19,4),
    conditions jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(conditions) = 'object'),
    priority integer NOT NULL DEFAULT 0,
    CONSTRAINT ck_loyalty_earning_rule_type CHECK (
      rule_type IN ('FIXED_PER_COMPLETED_BOOKING', 'PER_NIGHT', 'PER_SPEND_BLOCK')
    ),
    CONSTRAINT ck_loyalty_earning_amount CHECK (
      (rule_type = 'PER_SPEND_BLOCK' AND amount_block > 0)
      OR (rule_type <> 'PER_SPEND_BLOCK' AND amount_block IS NULL)
    ),
    UNIQUE (program_version_id, code)
);

CREATE TABLE loyalty_program_change_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    program_code varchar(64) NOT NULL,
    expected_program_version bigint,
    requested_by_subject_id uuid NOT NULL REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    reviewed_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    status varchar(24) NOT NULL DEFAULT 'PENDING',
    requested_payload jsonb NOT NULL CHECK (jsonb_typeof(requested_payload) = 'object'),
    request_hash char(64) NOT NULL,
    reason varchar(500) NOT NULL,
    review_reason varchar(500),
    idempotency_key varchar(160) NOT NULL,
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_loyalty_change_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'STALE')),
    CONSTRAINT ck_loyalty_change_checker CHECK (
      reviewed_by_subject_id IS NULL OR reviewed_by_subject_id <> requested_by_subject_id
    ),
    UNIQUE (requested_by_subject_id, idempotency_key)
);

CREATE TABLE loyalty_point_ledger (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_subject_id uuid NOT NULL REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    program_version_id uuid NOT NULL REFERENCES loyalty_program_versions(id) ON DELETE RESTRICT,
    source_type varchar(64) NOT NULL,
    source_id varchar(160) NOT NULL,
    source_revision bigint NOT NULL DEFAULT 1 CHECK (source_revision > 0),
    delta bigint NOT NULL CHECK (delta <> 0),
    reason varchar(500) NOT NULL,
    reversal_of uuid REFERENCES loyalty_point_ledger(id) ON DELETE RESTRICT,
    expires_at timestamptz,
    idempotency_key varchar(160) NOT NULL,
    created_by_subject_id uuid REFERENCES authorization_subjects(id) ON DELETE RESTRICT,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_type, source_id, source_revision),
    UNIQUE (customer_subject_id, idempotency_key),
    UNIQUE (reversal_of)
);
CREATE INDEX ix_loyalty_point_subject
  ON loyalty_point_ledger(customer_subject_id, occurred_at, id);

CREATE TABLE customer_loyalty_projections (
    customer_subject_id uuid PRIMARY KEY REFERENCES authorization_subjects(id) ON DELETE CASCADE,
    program_version_id uuid NOT NULL REFERENCES loyalty_program_versions(id) ON DELETE RESTRICT,
    qualifying_points bigint NOT NULL DEFAULT 0 CHECK (qualifying_points >= 0),
    tier_code varchar(64) NOT NULL,
    source_watermark timestamptz NOT NULL,
    projection_version bigint NOT NULL DEFAULT 1 CHECK (projection_version >= 1),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT sra.id, rp.permission_id, 'ALL'
FROM subject_role_assignments sra
JOIN roles r ON r.id = sra.role_id AND r.code = 'SUPER_ADMIN'
JOIN role_permissions rp ON rp.role_id = r.id
JOIN permissions p ON p.id = rp.permission_id
WHERE sra.revoked_at IS NULL
  AND p.code IN (
    'loyalty-program:read', 'loyalty-program:change-request',
    'loyalty-program:change-approve', 'loyalty-profile:read',
    'loyalty-point:adjust', 'property-attribute:read',
    'property-attribute:manage', 'property-attribute:publish',
    'booking-policy:read', 'booking-policy:change-request',
    'booking-policy:change-approve', 'booking-policy:simulate'
  )
ON CONFLICT DO NOTHING;
