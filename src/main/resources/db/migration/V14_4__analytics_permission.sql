SET search_path TO app, extensions, public;

INSERT INTO permissions(resource, action, description)
VALUES ('analytics', 'read', 'Read governed operational and commercial analytics')
ON CONFLICT (resource, action) DO UPDATE SET
    description = EXCLUDED.description,
    active = true,
    deprecated_at = NULL;

INSERT INTO role_permissions(role_id, permission_id)
SELECT role.id, permission.id
FROM roles role
JOIN permissions permission ON permission.code = 'analytics:read'
WHERE role.code = 'SUPER_ADMIN'
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT role.id, permission.id, 'ALL', true
FROM roles role
JOIN permissions permission ON permission.code = 'analytics:read'
WHERE role.code = 'SUPER_ADMIN'
ON CONFLICT DO NOTHING;

INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT assignment.id, permission.id, 'ALL'
FROM subject_role_assignments assignment
JOIN roles role ON role.id = assignment.role_id AND role.code = 'SUPER_ADMIN'
JOIN permissions permission ON permission.code = 'analytics:read'
WHERE assignment.revoked_at IS NULL
  AND assignment.valid_from <= now()
  AND (assignment.valid_until IS NULL OR assignment.valid_until > now())
ON CONFLICT DO NOTHING;
