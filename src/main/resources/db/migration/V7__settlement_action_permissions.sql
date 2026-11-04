SET search_path TO app, extensions, public;

INSERT INTO permissions(resource, action, description) VALUES
    ('settlement', 'create', 'Mở kỳ quyết toán'),
    ('settlement', 'update', 'Tính toán và cập nhật kỳ quyết toán'),
    ('settlement', 'payout', 'Tạo khoản phải trả và ghi nhận chi trả')
ON CONFLICT (resource, action) DO UPDATE SET
    description = EXCLUDED.description,
    active = true,
    deprecated_at = NULL;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('settlement:create', 'settlement:update', 'settlement:payout')
WHERE r.code IN ('SUPER_ADMIN', 'FINANCE_OPERATOR')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ALL', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'SUPER_ADMIN'
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code IN ('settlement:create', 'settlement:update', 'settlement:payout')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, scope.scope_type, scope.scope_type = 'ASSIGNED'
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'FINANCE_OPERATOR'
JOIN permissions p ON p.id = rp.permission_id
CROSS JOIN (VALUES ('ASSIGNED'), ('ALL')) AS scope(scope_type)
WHERE p.code IN ('settlement:create', 'settlement:update', 'settlement:payout')
ON CONFLICT DO NOTHING;
