SET search_path TO app, extensions, public;

-- A notification inbox is always addressable by the authenticated account itself.
-- Broader ASSIGNED/ALL policies remain available for future support tooling, but
-- they do not replace SELF on the personal stream.
INSERT INTO role_permission_policies(
    role_id, permission_id, scope_type, default_scope
)
SELECT rp.role_id, rp.permission_id, 'SELF', true
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id AND p.active
WHERE p.code IN ('notification:read', 'notification:update')
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = true;

INSERT INTO subject_role_permission_scopes(
    assignment_id, permission_id, scope_type
)
SELECT sra.id, rp.permission_id, 'SELF'
FROM subject_role_assignments sra
JOIN role_permissions rp ON rp.role_id = sra.role_id
JOIN permissions p ON p.id = rp.permission_id AND p.active
WHERE p.code IN ('notification:read', 'notification:update')
  AND sra.revoked_at IS NULL
  AND sra.valid_from <= now()
  AND (sra.valid_until IS NULL OR sra.valid_until > now())
ON CONFLICT DO NOTHING;

UPDATE authorization_subjects s
SET authorization_version = authorization_version + 1,
    updated_at = now()
WHERE EXISTS (
    SELECT 1
    FROM subject_role_assignments sra
    JOIN subject_role_permission_scopes srps ON srps.assignment_id = sra.id
    JOIN permissions p ON p.id = srps.permission_id
    WHERE sra.subject_id = s.id
      AND p.code IN ('notification:read', 'notification:update')
      AND srps.scope_type = 'SELF'
      AND sra.revoked_at IS NULL
);
