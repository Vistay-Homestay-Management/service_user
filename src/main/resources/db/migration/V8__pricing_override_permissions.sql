SET search_path TO app, extensions, public;

INSERT INTO permissions(resource, action, description) VALUES
    ('pricing', 'override', 'Apply an audited manual pricing override'),
    ('pricing', 'approve-large-override', 'Approve a pricing reduction above the configured threshold')
ON CONFLICT (resource, action) DO UPDATE SET
    description = EXCLUDED.description,
    active = true,
    deprecated_at = NULL;

-- SUPER_ADMIN receives both actions. MANAGER may apply an override but cannot
-- approve a large reduction by default. No other role receives either action.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON
       (r.code = 'SUPER_ADMIN'
        AND p.code IN ('pricing:override', 'pricing:approve-large-override'))
    OR (r.code = 'MANAGER' AND p.code = 'pricing:override')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ALL', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'SUPER_ADMIN'
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code IN ('pricing:override', 'pricing:approve-large-override')
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = true;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, scope.scope_type, scope.scope_type = 'ASSIGNED'
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'MANAGER'
JOIN permissions p ON p.id = rp.permission_id AND p.code = 'pricing:override'
CROSS JOIN (VALUES ('ASSIGNED'), ('ALL')) AS scope(scope_type)
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = EXCLUDED.default_scope;

INSERT INTO role_permission_partition_policies(role_id, permission_id, partition_type)
SELECT rp.role_id, rp.permission_id, 'BRANCH'
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'MANAGER'
JOIN permissions p ON p.id = rp.permission_id AND p.code = 'pricing:override'
ON CONFLICT DO NOTHING;

-- Existing, non-revoked SUPER_ADMIN assignments receive the newly introduced
-- grants at ALL so their effective catalog remains complete.
INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT sra.id, p.id, 'ALL'
FROM subject_role_assignments sra
JOIN roles r ON r.id = sra.role_id AND r.code = 'SUPER_ADMIN'
JOIN permissions p ON p.code IN ('pricing:override', 'pricing:approve-large-override')
WHERE sra.revoked_at IS NULL
ON CONFLICT DO NOTHING;

-- Existing MANAGER assignments receive only the default ASSIGNED grant.
INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT sra.id, p.id, 'ASSIGNED'
FROM subject_role_assignments sra
JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
JOIN permissions p ON p.code = 'pricing:override'
WHERE sra.revoked_at IS NULL
ON CONFLICT DO NOTHING;

-- A manager's branch is an opaque Property-owned identifier. It is copied
-- only when the User profile already has an explicit branch reference.
INSERT INTO subject_role_permission_partitions(
    assignment_id, permission_id, partition_type, partition_id
)
SELECT sra.id, p.id, 'BRANCH', au.branch_reference_id
FROM subject_role_assignments sra
JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
JOIN admin_users au ON au.authorization_subject_id = sra.subject_id
JOIN permissions p ON p.code = 'pricing:override'
WHERE sra.revoked_at IS NULL
  AND au.branch_reference_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- Versioned cache keys make the catalog change immediately visible only to
-- subjects whose assignment is effective at migration time.
UPDATE authorization_subjects s
SET authorization_version = authorization_version + 1,
    updated_at = now()
WHERE EXISTS (
    SELECT 1
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    WHERE sra.subject_id = s.id
      AND r.code IN ('SUPER_ADMIN', 'MANAGER')
      AND sra.revoked_at IS NULL
      AND sra.valid_from <= now()
      AND (sra.valid_until IS NULL OR sra.valid_until > now())
);
