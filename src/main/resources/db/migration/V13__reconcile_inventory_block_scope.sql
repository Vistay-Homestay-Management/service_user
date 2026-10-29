SET search_path TO app, extensions, public;

-- V12 repaired legacy inventory:block evidence before installing its guards.
-- A concurrent writer could therefore commit between the backfill and trigger
-- creation. Acquire every catalog/evidence table up front and fail fast rather
-- than running a partial reconciliation against moving authorization data.
-- Flyway keeps these locks until the transactional migration commits.
LOCK TABLE
    roles,
    permissions,
    authorization_partition_types,
    role_permissions,
    role_permission_policies,
    role_permission_partition_policies,
    authorization_subjects,
    admin_users,
    subject_role_assignments,
    subject_role_permission_scopes,
    subject_role_permission_partitions
IN EXCLUSIVE MODE NOWAIT;

CREATE TEMP TABLE inventory_block_reconciled_subjects (
    subject_id uuid PRIMARY KEY
) ON COMMIT DROP;

-- Reassert the exact catalog maximum: SUPER_ADMIN ALL and MANAGER ASSIGNED.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code = 'inventory:block' AND p.active
WHERE r.code IN ('SUPER_ADMIN', 'MANAGER')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ALL', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'SUPER_ADMIN'
JOIN permissions p ON p.id = rp.permission_id AND p.code = 'inventory:block'
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = true;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ASSIGNED', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'MANAGER'
JOIN permissions p ON p.id = rp.permission_id AND p.code = 'inventory:block'
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = true;

DELETE FROM role_permission_policies rpp
USING roles r, permissions p
WHERE rpp.role_id = r.id
  AND rpp.permission_id = p.id
  AND p.code = 'inventory:block'
  AND (
      (r.code = 'SUPER_ADMIN' AND rpp.scope_type <> 'ALL')
      OR (r.code = 'MANAGER' AND rpp.scope_type <> 'ASSIGNED')
  );

-- Preserve effective allowed grants while narrowing any residue. Missing rows
-- remain missing so an explicit reduction is never re-granted.
WITH inserted_super_all AS (
    INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
    SELECT DISTINCT srps.assignment_id, srps.permission_id, 'ALL'
    FROM subject_role_permission_scopes srps
    JOIN subject_role_assignments sra ON sra.id = srps.assignment_id
    JOIN roles r ON r.id = sra.role_id AND r.code = 'SUPER_ADMIN'
    JOIN permissions p ON p.id = srps.permission_id AND p.code = 'inventory:block'
    WHERE srps.scope_type <> 'ALL'
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_super_all inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

WITH removed_super_non_all AS (
    DELETE FROM subject_role_permission_scopes srps
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srps.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code = 'SUPER_ADMIN'
      AND srps.permission_id = p.id
      AND p.code = 'inventory:block'
      AND srps.scope_type <> 'ALL'
    RETURNING sra.subject_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_super_non_all
ON CONFLICT DO NOTHING;

WITH inserted_manager_assigned AS (
    INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
    SELECT DISTINCT srps.assignment_id, srps.permission_id, 'ASSIGNED'
    FROM subject_role_permission_scopes srps
    JOIN subject_role_assignments sra ON sra.id = srps.assignment_id
    JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
    JOIN permissions p ON p.id = srps.permission_id AND p.code = 'inventory:block'
    WHERE srps.scope_type <> 'ASSIGNED'
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_manager_assigned inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

WITH removed_manager_non_assigned AS (
    DELETE FROM subject_role_permission_scopes srps
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srps.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code = 'MANAGER'
      AND srps.permission_id = p.id
      AND p.code = 'inventory:block'
      AND srps.scope_type <> 'ASSIGNED'
    RETURNING sra.subject_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_manager_non_assigned
ON CONFLICT DO NOTHING;

-- Scope rows are independent of role_permissions. Remove both subject evidence
-- tables explicitly before deleting unauthorized catalog rows.
WITH removed_forbidden_partitions AS (
    DELETE FROM subject_role_permission_partitions srpp
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srpp.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code NOT IN ('SUPER_ADMIN', 'MANAGER')
      AND srpp.permission_id = p.id
      AND p.code = 'inventory:block'
    RETURNING sra.subject_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_forbidden_partitions
ON CONFLICT DO NOTHING;

WITH removed_forbidden_scopes AS (
    DELETE FROM subject_role_permission_scopes srps
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srps.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code NOT IN ('SUPER_ADMIN', 'MANAGER')
      AND srps.permission_id = p.id
      AND p.code = 'inventory:block'
    RETURNING sra.subject_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_forbidden_scopes
ON CONFLICT DO NOTHING;

WITH removed_super_partitions AS (
    DELETE FROM subject_role_permission_partitions srpp
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srpp.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code = 'SUPER_ADMIN'
      AND srpp.permission_id = p.id
      AND p.code = 'inventory:block'
    RETURNING sra.subject_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_super_partitions
ON CONFLICT DO NOTHING;

DELETE FROM role_permissions rp
USING roles r, permissions p
WHERE rp.role_id = r.id
  AND r.code NOT IN ('SUPER_ADMIN', 'MANAGER')
  AND rp.permission_id = p.id
  AND p.code = 'inventory:block';

DELETE FROM role_permission_partition_policies rpp
USING roles r, permissions p
WHERE rpp.role_id = r.id
  AND rpp.permission_id = p.id
  AND p.code = 'inventory:block'
  AND (r.code <> 'MANAGER' OR rpp.partition_type <> 'BRANCH');

INSERT INTO role_permission_partition_policies(role_id, permission_id, partition_type)
SELECT rp.role_id, rp.permission_id, 'BRANCH'
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'MANAGER'
JOIN permissions p ON p.id = rp.permission_id AND p.code = 'inventory:block'
ON CONFLICT DO NOTHING;

WITH removed_stale_manager_partitions AS (
    DELETE FROM subject_role_permission_partitions srpp
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srpp.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code = 'MANAGER'
      AND srpp.permission_id = p.id
      AND p.code = 'inventory:block'
      AND (
          sra.revoked_at IS NOT NULL
          OR srpp.partition_type <> 'BRANCH'
          OR NOT EXISTS (
              SELECT 1
              FROM subject_role_permission_scopes srps
              WHERE srps.assignment_id = sra.id
                AND srps.permission_id = p.id
                AND srps.scope_type = 'ASSIGNED'
          )
          OR NOT EXISTS (
              SELECT 1
              FROM admin_users au
              WHERE au.authorization_subject_id = sra.subject_id
                AND au.branch_reference_id IS NOT NULL
                AND au.branch_reference_id = srpp.partition_id
          )
      )
    RETURNING sra.subject_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_stale_manager_partitions
ON CONFLICT DO NOTHING;

WITH inserted_current_manager_partitions AS (
    INSERT INTO subject_role_permission_partitions(
        assignment_id, permission_id, partition_type, partition_id
    )
    SELECT sra.id, p.id, 'BRANCH', au.branch_reference_id
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
    JOIN admin_users au ON au.authorization_subject_id = sra.subject_id
    JOIN permissions p ON p.code = 'inventory:block' AND p.active
    JOIN subject_role_permission_scopes srps
      ON srps.assignment_id = sra.id
     AND srps.permission_id = p.id
     AND srps.scope_type = 'ASSIGNED'
    WHERE sra.revoked_at IS NULL
      AND au.branch_reference_id IS NOT NULL
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO inventory_block_reconciled_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_current_manager_partitions inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

-- One version bump per subject invalidates versioned caches for every effective
-- reconciliation, regardless of how many rows were repaired.
UPDATE authorization_subjects subject
SET authorization_version = authorization_version + 1,
    updated_at = now()
WHERE subject.id IN (
    SELECT changed.subject_id
    FROM inventory_block_reconciled_subjects changed
);
