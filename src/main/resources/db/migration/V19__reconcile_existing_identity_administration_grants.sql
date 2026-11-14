SET search_path TO app, extensions, public;

-- V18 added the administration permissions to the role-policy catalog. Existing
-- assignments still used the compatibility projection populated when the role
-- was originally assigned, so their viewer snapshot did not expose the new
-- actions. Rebuild only the newly introduced grants and advance the subject
-- version so versioned Redis snapshots cannot keep serving the stale policy.
WITH identity_permissions AS (
    SELECT id
    FROM permissions
    WHERE active
      AND code IN (
          'customer-profile:create', 'admin-profile:create', 'host-profile:create',
          'customer-account:provision', 'host-account:provision', 'admin-account:provision',
          'identity-policy:read', 'identity-policy:update'
      )
)
INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT assignment.id, policy.permission_id, policy.scope_type
FROM subject_role_assignments assignment
JOIN roles role ON role.id = assignment.role_id
JOIN role_permission_policies policy ON policy.role_id = role.id
JOIN identity_permissions permission ON permission.id = policy.permission_id
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

