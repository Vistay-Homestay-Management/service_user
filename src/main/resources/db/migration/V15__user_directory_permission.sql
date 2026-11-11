SET search_path TO app, extensions, public;

INSERT INTO permissions(resource, action, description)
VALUES ('user', 'read', 'Xem danh bạ hồ sơ khách hàng, nhân viên và chủ nhà')
ON CONFLICT (resource, action) DO UPDATE SET
    description = EXCLUDED.description,
    active = true,
    deprecated_at = NULL;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN', 'MANAGER')
  AND r.audience = 'ADMIN'
  AND p.code = 'user:read'
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT r.id, p.id, 'ALL', true
FROM roles r
CROSS JOIN permissions p
WHERE r.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN', 'MANAGER')
  AND r.audience = 'ADMIN'
  AND p.code = 'user:read'
ON CONFLICT DO NOTHING;

INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT assignment.id, policy.permission_id, policy.scope_type
FROM subject_role_assignments assignment
JOIN role_permission_policies policy ON policy.role_id = assignment.role_id
JOIN permissions permission ON permission.id = policy.permission_id
WHERE permission.code = 'user:read'
ON CONFLICT DO NOTHING;

UPDATE authorization_catalog_state
SET catalog_version = catalog_version + 1,
    updated_at = now()
WHERE singleton;
