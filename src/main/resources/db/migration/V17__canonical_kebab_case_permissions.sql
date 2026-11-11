SET search_path TO app, extensions, public;

INSERT INTO permissions(resource, action, description) VALUES
    ('account', 'revoke-session', 'Thu hồi phiên tài khoản'),
    ('booking', 'check-in', 'Check-in booking'),
    ('booking', 'check-out', 'Check-out booking'),
    ('customer-sensitive', 'read', 'Xem dữ liệu khách hàng nhạy cảm')
ON CONFLICT (resource, action) DO UPDATE SET
    description = EXCLUDED.description,
    active = true,
    deprecated_at = NULL;

INSERT INTO permission_aliases(alias_code, permission_id)
SELECT mapping.alias_code, canonical.id
FROM (VALUES
    ('account:revoke_session', 'account:revoke-session'),
    ('booking:check_in', 'booking:check-in'),
    ('booking:check_out', 'booking:check-out'),
    ('customer:read_sensitive', 'customer-sensitive:read')
) AS mapping(alias_code, canonical_code)
JOIN permissions canonical ON canonical.code = mapping.canonical_code
ON CONFLICT (alias_code) DO UPDATE
SET permission_id = EXCLUDED.permission_id;

INSERT INTO role_permissions(role_id, permission_id)
SELECT legacy_grant.role_id, canonical.id
FROM role_permissions legacy_grant
JOIN permissions legacy ON legacy.id = legacy_grant.permission_id
JOIN (VALUES
    ('account:revoke_session', 'account:revoke-session'),
    ('booking:check_in', 'booking:check-in'),
    ('booking:check_out', 'booking:check-out'),
    ('customer:read_sensitive', 'customer-sensitive:read')
) AS mapping(alias_code, canonical_code) ON mapping.alias_code = legacy.code
JOIN permissions canonical ON canonical.code = mapping.canonical_code
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT legacy_policy.role_id, canonical.id,
       legacy_policy.scope_type, legacy_policy.default_scope
FROM role_permission_policies legacy_policy
JOIN permissions legacy ON legacy.id = legacy_policy.permission_id
JOIN (VALUES
    ('account:revoke_session', 'account:revoke-session'),
    ('booking:check_in', 'booking:check-in'),
    ('booking:check_out', 'booking:check-out'),
    ('customer:read_sensitive', 'customer-sensitive:read')
) AS mapping(alias_code, canonical_code) ON mapping.alias_code = legacy.code
JOIN permissions canonical ON canonical.code = mapping.canonical_code
ON CONFLICT DO NOTHING;

INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT legacy_scope.assignment_id, canonical.id, legacy_scope.scope_type
FROM subject_role_permission_scopes legacy_scope
JOIN permissions legacy ON legacy.id = legacy_scope.permission_id
JOIN (VALUES
    ('account:revoke_session', 'account:revoke-session'),
    ('booking:check_in', 'booking:check-in'),
    ('booking:check_out', 'booking:check-out'),
    ('customer:read_sensitive', 'customer-sensitive:read')
) AS mapping(alias_code, canonical_code) ON mapping.alias_code = legacy.code
JOIN permissions canonical ON canonical.code = mapping.canonical_code
ON CONFLICT DO NOTHING;

UPDATE permissions
SET active = false, deprecated_at = COALESCE(deprecated_at, now())
WHERE code IN (
    'account:revoke_session',
    'booking:check_in',
    'booking:check_out',
    'customer:read_sensitive',
    'booking:read_sensitive'
);

UPDATE authorization_catalog_state
SET catalog_version = catalog_version + 1, updated_at = now()
WHERE singleton;
