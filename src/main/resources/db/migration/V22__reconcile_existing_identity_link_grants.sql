SET search_path TO app, extensions, public;

-- V16 granted the protected administrator roles access to the identity-link
-- management surface, but assignments created before V16 kept their older
-- compatibility projection. Rebuild the missing subject scopes so the runtime
-- viewer and the role-policy catalog describe the same effective policy.
WITH identity_link_permissions AS (
    SELECT id
    FROM permissions
    WHERE active
      AND code IN (
          'identity-document:manage',
          'identity-link:read',
          'identity-link:approve',
          'identity-link:reject'
      )
)
INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT assignment.id, policy.permission_id, policy.scope_type
FROM subject_role_assignments assignment
JOIN roles role ON role.id = assignment.role_id
JOIN role_permission_policies policy ON policy.role_id = role.id
JOIN identity_link_permissions permission ON permission.id = policy.permission_id
WHERE role.audience = 'ADMIN'
  AND role.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')
  AND role.active
  AND assignment.revoked_at IS NULL
  AND assignment.valid_from <= now()
  AND (assignment.valid_until IS NULL OR assignment.valid_until > now())
ON CONFLICT DO NOTHING;

UPDATE authorization_subjects subject
SET authorization_version = authorization_version + 1,
    updated_at = now()
WHERE subject.active
  AND EXISTS (
      SELECT 1
      FROM subject_role_assignments assignment
      JOIN roles role ON role.id = assignment.role_id
      WHERE assignment.subject_id = subject.id
        AND role.audience = 'ADMIN'
        AND role.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')
        AND role.active
        AND assignment.revoked_at IS NULL
        AND assignment.valid_from <= now()
        AND (assignment.valid_until IS NULL OR assignment.valid_until > now())
  );
