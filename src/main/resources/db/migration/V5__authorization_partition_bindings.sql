SET search_path TO app, extensions, public;

CREATE TABLE authorization_partition_types (
    code varchar(32) PRIMARY KEY,
    description varchar(255) NOT NULL,
    active boolean NOT NULL DEFAULT true,
    CONSTRAINT ck_authorization_partition_type_code
        CHECK (code = upper(code) AND code ~ '^[A-Z][A-Z0-9_]{1,31}$')
);

INSERT INTO authorization_partition_types(code, description) VALUES
    ('PROPERTY', 'One property'),
    ('BUILDING', 'One building inside a property'),
    ('BRANCH', 'Operational branch'),
    ('AREA', 'Configured operational area'),
    ('CITY', 'City-level partition'),
    ('ORGANIZATION', 'Organization or legal entity');

CREATE TABLE role_permission_partition_policies (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    partition_type varchar(32) NOT NULL REFERENCES authorization_partition_types(code),
    PRIMARY KEY (role_id, permission_id, partition_type),
    CONSTRAINT fk_partition_policy_permission
        FOREIGN KEY (role_id, permission_id)
        REFERENCES role_permissions(role_id, permission_id) ON DELETE CASCADE
);

CREATE TABLE subject_role_permission_partitions (
    assignment_id uuid NOT NULL REFERENCES subject_role_assignments(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    partition_type varchar(32) NOT NULL REFERENCES authorization_partition_types(code),
    partition_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (assignment_id, permission_id, partition_type, partition_id)
);

CREATE INDEX ix_subject_permission_partitions_assignment
    ON subject_role_permission_partitions(assignment_id, permission_id);

COMMENT ON COLUMN subject_role_permission_partitions.partition_id IS
    'Opaque domain identifier resolved only by the service owning the protected resource';
