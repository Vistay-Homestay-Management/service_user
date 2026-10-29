SET search_path TO app, extensions, public;

-- Pricing profile reads, authoring, and publication are branch-owned actions
-- for MANAGER. Repair the legacy V3 ASSIGNED/optional-ALL catalog while
-- preserving SUPER_ADMIN as the only role with these actions at ALL.
CREATE TEMP TABLE manager_pricing_management_changed_subjects (
    subject_id uuid PRIMARY KEY
) ON COMMIT DROP;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
WHERE r.code IN ('SUPER_ADMIN', 'MANAGER')
  AND p.active
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ALL', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'SUPER_ADMIN'
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = true;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ASSIGNED', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'MANAGER'
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = true;

-- Preserve the effective permission set while narrowing legacy ALL grants.
-- Missing pricing scopes may be the result of a deliberate maker-checker
-- reduction, so this migration must not re-grant a permission merely because
-- the MANAGER role template contains it.
INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
SELECT srps.assignment_id, srps.permission_id, 'ASSIGNED'
FROM subject_role_permission_scopes srps
JOIN subject_role_assignments sra ON sra.id = srps.assignment_id
JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
JOIN permissions p ON p.id = srps.permission_id
WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
  AND srps.scope_type = 'ALL'
ON CONFLICT DO NOTHING;

WITH removed_manager_all AS (
    DELETE FROM subject_role_permission_scopes srps
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srps.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code = 'MANAGER'
      AND srps.permission_id = p.id
      AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
      AND srps.scope_type = 'ALL'
    RETURNING sra.subject_id
)
INSERT INTO manager_pricing_management_changed_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_manager_all
ON CONFLICT DO NOTHING;

DELETE FROM role_permission_policies rpp
USING roles r, permissions p
WHERE rpp.role_id = r.id
  AND r.code = 'MANAGER'
  AND rpp.permission_id = p.id
  AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
  AND rpp.scope_type = 'ALL';

-- A MANAGER pricing grant may only carry a BRANCH partition policy.
DELETE FROM role_permission_partition_policies rpp
USING roles r, permissions p
WHERE rpp.role_id = r.id
  AND r.code = 'MANAGER'
  AND rpp.permission_id = p.id
  AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
  AND rpp.partition_type <> 'BRANCH';

INSERT INTO role_permission_partition_policies(role_id, permission_id, partition_type)
SELECT rp.role_id, rp.permission_id, 'BRANCH'
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'MANAGER'
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
ON CONFLICT DO NOTHING;

-- Repair existing active assignments before installing forward-only hooks.
WITH inserted_super_all AS (
    INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
    SELECT sra.id, p.id, 'ALL'
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id AND r.code = 'SUPER_ADMIN'
    JOIN permissions p ON p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
                         AND p.active
    WHERE sra.revoked_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO manager_pricing_management_changed_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_super_all inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

WITH removed_stale_partitions AS (
    DELETE FROM subject_role_permission_partitions srpp
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srpp.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code = 'MANAGER'
      AND srpp.permission_id = p.id
      AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
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
INSERT INTO manager_pricing_management_changed_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_stale_partitions
ON CONFLICT DO NOTHING;

WITH inserted_current_partitions AS (
    INSERT INTO subject_role_permission_partitions(
        assignment_id, permission_id, partition_type, partition_id
    )
    SELECT sra.id, p.id, 'BRANCH', au.branch_reference_id
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
    JOIN admin_users au ON au.authorization_subject_id = sra.subject_id
    JOIN permissions p ON p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
                         AND p.active
    JOIN subject_role_permission_scopes srps
      ON srps.assignment_id = sra.id
     AND srps.permission_id = p.id
     AND srps.scope_type = 'ASSIGNED'
    WHERE sra.revoked_at IS NULL
      AND au.branch_reference_id IS NOT NULL
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO manager_pricing_management_changed_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_current_partitions inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

UPDATE authorization_subjects subject
SET authorization_version = authorization_version + 1,
    updated_at = now()
WHERE subject.id IN (
    SELECT changed.subject_id
    FROM manager_pricing_management_changed_subjects changed
);

CREATE OR REPLACE FUNCTION sync_manager_pricing_management_assignment(
    target_assignment_id uuid,
    ensure_default_scopes boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    manager_subject_id uuid;
    assignment_revoked_at timestamptz;
    assignment_role_code varchar(64);
    manager_branch_id uuid;
BEGIN
    SELECT sra.subject_id, sra.revoked_at, r.code
    INTO manager_subject_id, assignment_revoked_at, assignment_role_code
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    WHERE sra.id = target_assignment_id;

    IF NOT FOUND OR assignment_role_code <> 'MANAGER' THEN
        RETURN;
    END IF;

    DELETE FROM subject_role_permission_scopes srps
    USING permissions p
    WHERE srps.assignment_id = target_assignment_id
      AND srps.permission_id = p.id
      AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
      AND srps.scope_type = 'ALL';

    IF assignment_revoked_at IS NOT NULL THEN
        DELETE FROM subject_role_permission_partitions srpp
        USING permissions p
        WHERE srpp.assignment_id = target_assignment_id
          AND srpp.permission_id = p.id
          AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve');
        RETURN;
    END IF;

    IF ensure_default_scopes THEN
        INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
        SELECT target_assignment_id, p.id, 'ASSIGNED'
        FROM permissions p
        WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
          AND p.active
        ON CONFLICT DO NOTHING;
    END IF;

    SELECT au.branch_reference_id
    INTO manager_branch_id
    FROM admin_users au
    WHERE au.authorization_subject_id = manager_subject_id;

    DELETE FROM subject_role_permission_partitions srpp
    USING permissions p
    WHERE srpp.assignment_id = target_assignment_id
      AND srpp.permission_id = p.id
      AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
      AND (
          srpp.partition_type <> 'BRANCH'
          OR manager_branch_id IS NULL
          OR srpp.partition_id <> manager_branch_id
          OR NOT EXISTS (
              SELECT 1
              FROM subject_role_permission_scopes srps
              WHERE srps.assignment_id = target_assignment_id
                AND srps.permission_id = p.id
                AND srps.scope_type = 'ASSIGNED'
          )
      );

    IF manager_branch_id IS NOT NULL THEN
        INSERT INTO subject_role_permission_partitions(
            assignment_id, permission_id, partition_type, partition_id
        )
        SELECT target_assignment_id, p.id, 'BRANCH', manager_branch_id
        FROM permissions p
        JOIN subject_role_permission_scopes srps
          ON srps.assignment_id = target_assignment_id
         AND srps.permission_id = p.id
         AND srps.scope_type = 'ASSIGNED'
        WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
          AND p.active
        ON CONFLICT DO NOTHING;
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION sync_manager_pricing_management_assignment_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    PERFORM sync_manager_pricing_management_assignment(NEW.id, TG_OP = 'INSERT');
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_pricing_management_assignment_after_change
AFTER INSERT OR UPDATE OF revoked_at
ON subject_role_assignments
FOR EACH ROW
EXECUTE FUNCTION sync_manager_pricing_management_assignment_trigger();

CREATE OR REPLACE FUNCTION sync_manager_pricing_management_branch_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    manager_assignment_id uuid;
BEGIN
    IF OLD.branch_reference_id IS NOT DISTINCT FROM NEW.branch_reference_id THEN
        RETURN NEW;
    END IF;

    FOR manager_assignment_id IN
        SELECT sra.id
        FROM subject_role_assignments sra
        JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
        WHERE sra.subject_id = NEW.authorization_subject_id
          AND sra.revoked_at IS NULL
    LOOP
        PERFORM sync_manager_pricing_management_assignment(manager_assignment_id, false);
    END LOOP;

    -- V9's sibling branch trigger bumps authorization_version exactly once
    -- for the same active MANAGER assignment.
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_pricing_management_branch_after_change
AFTER UPDATE OF branch_reference_id
ON admin_users
FOR EACH ROW
EXECUTE FUNCTION sync_manager_pricing_management_branch_trigger();

CREATE OR REPLACE FUNCTION sync_manager_pricing_management_scope_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM sync_manager_pricing_management_assignment(OLD.assignment_id, false);
        RETURN OLD;
    END IF;
    PERFORM sync_manager_pricing_management_assignment(NEW.assignment_id, false);
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_pricing_management_scope_after_insert
AFTER INSERT
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_manager_pricing_management_scope_trigger();

CREATE TRIGGER sync_manager_pricing_management_scope_after_delete
AFTER DELETE
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_manager_pricing_management_scope_trigger();

-- Database-level guards keep maker-checker or future direct SQL paths from
-- escalating a MANAGER pricing profile action to ALL.
CREATE OR REPLACE FUNCTION reject_manager_pricing_management_all_policy_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF NEW.scope_type = 'ALL' AND EXISTS (
        SELECT 1
        FROM roles r, permissions p
        WHERE r.id = NEW.role_id
          AND r.code = 'MANAGER'
          AND p.id = NEW.permission_id
          AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
    ) THEN
        RAISE EXCEPTION 'MANAGER cannot use branch-bound pricing permissions at ALL policy'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_manager_pricing_management_all_policy
BEFORE INSERT OR UPDATE OF role_id, permission_id, scope_type
ON role_permission_policies
FOR EACH ROW
EXECUTE FUNCTION reject_manager_pricing_management_all_policy_trigger();

CREATE OR REPLACE FUNCTION reject_manager_pricing_management_all_scope_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF NEW.scope_type = 'ALL' AND EXISTS (
        SELECT 1
        FROM subject_role_assignments sra
        JOIN roles r ON r.id = sra.role_id
        JOIN permissions p ON p.id = NEW.permission_id
        WHERE sra.id = NEW.assignment_id
          AND r.code = 'MANAGER'
          AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
    ) THEN
        RAISE EXCEPTION 'MANAGER cannot receive branch-bound pricing permission at ALL'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_manager_pricing_management_all_scope
BEFORE INSERT OR UPDATE OF assignment_id, permission_id, scope_type
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION reject_manager_pricing_management_all_scope_trigger();

-- Partition rows are themselves effective grants in authorization snapshots.
-- Reject direct SQL or future code paths that try to attach a MANAGER pricing
-- permission to anything except that subject's current branch. The matching
-- ASSIGNED scope must already exist so an orphan partition cannot create a
-- permission by itself.
CREATE OR REPLACE FUNCTION reject_invalid_manager_pricing_management_partition_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    manager_subject_id uuid;
    assignment_revoked_at timestamptz;
    manager_branch_id uuid;
BEGIN
    SELECT sra.subject_id, sra.revoked_at, au.branch_reference_id
    INTO manager_subject_id, assignment_revoked_at, manager_branch_id
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
    JOIN permissions p ON p.id = NEW.permission_id
        AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
    LEFT JOIN admin_users au ON au.authorization_subject_id = sra.subject_id
    WHERE sra.id = NEW.assignment_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF assignment_revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'Revoked MANAGER assignment cannot receive a pricing partition'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.partition_type <> 'BRANCH'
       OR manager_branch_id IS NULL
       OR NEW.partition_id <> manager_branch_id THEN
        RAISE EXCEPTION 'MANAGER pricing partition must match the current BRANCH'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM subject_role_permission_scopes srps
        WHERE srps.assignment_id = NEW.assignment_id
          AND srps.permission_id = NEW.permission_id
          AND srps.scope_type = 'ASSIGNED'
    ) THEN
        RAISE EXCEPTION 'MANAGER pricing partition requires an ASSIGNED scope'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_invalid_manager_pricing_management_partition
BEFORE INSERT OR UPDATE OF assignment_id, permission_id, partition_type, partition_id
ON subject_role_permission_partitions
FOR EACH ROW
EXECUTE FUNCTION reject_invalid_manager_pricing_management_partition_trigger();
