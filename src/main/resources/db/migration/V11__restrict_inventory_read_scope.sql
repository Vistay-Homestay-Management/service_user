SET search_path TO app, extensions, public;

-- Inventory availability is globally readable only by SUPER_ADMIN and CTV.
-- Operational employees must be bound to the current branch recorded on their
-- admin profile. Existing missing grants are deliberate reductions and are not
-- recreated by this migration.
CREATE TEMP TABLE inventory_read_changed_subjects (
    subject_id uuid PRIMARY KEY
) ON COMMIT DROP;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code = 'inventory:read' AND p.active
WHERE r.code IN ('SUPER_ADMIN', 'CTV', 'MANAGER', 'RECEPTIONIST', 'STAFF')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ALL', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code IN ('SUPER_ADMIN', 'CTV')
JOIN permissions p ON p.id = rp.permission_id AND p.code = 'inventory:read'
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = true;

DELETE FROM role_permission_policies rpp
USING roles r, permissions p
WHERE rpp.role_id = r.id
  AND r.code IN ('SUPER_ADMIN', 'CTV')
  AND rpp.permission_id = p.id
  AND p.code = 'inventory:read'
  AND rpp.scope_type <> 'ALL';

INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
SELECT rp.role_id, rp.permission_id, 'ASSIGNED', true
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
    AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
JOIN permissions p ON p.id = rp.permission_id AND p.code = 'inventory:read'
ON CONFLICT (role_id, permission_id, scope_type)
DO UPDATE SET default_scope = true;

DELETE FROM role_permission_policies rpp
USING roles r, permissions p
WHERE rpp.role_id = r.id
  AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
  AND rpp.permission_id = p.id
  AND p.code = 'inventory:read'
  AND rpp.scope_type <> 'ASSIGNED';

-- Only BRANCH is a valid partition vocabulary entry for operational reads.
DELETE FROM role_permission_partition_policies rpp
USING roles r, permissions p
WHERE rpp.role_id = r.id
  AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
  AND rpp.permission_id = p.id
  AND p.code = 'inventory:read'
  AND rpp.partition_type <> 'BRANCH';

INSERT INTO role_permission_partition_policies(role_id, permission_id, partition_type)
SELECT rp.role_id, rp.permission_id, 'BRANCH'
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
    AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
JOIN permissions p ON p.id = rp.permission_id AND p.code = 'inventory:read'
ON CONFLICT DO NOTHING;

-- ALL/OWN/SELF legacy rows all mean that this assignment still has the
-- permission. Preserve that effective permission while narrowing it to the
-- assignment's current BRANCH. An assignment with no row stays reduced.
WITH inserted_assigned AS (
    INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
    SELECT DISTINCT srps.assignment_id, srps.permission_id, 'ASSIGNED'
    FROM subject_role_permission_scopes srps
    JOIN subject_role_assignments sra ON sra.id = srps.assignment_id
    JOIN roles r ON r.id = sra.role_id
        AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
    JOIN permissions p ON p.id = srps.permission_id AND p.code = 'inventory:read'
    WHERE srps.scope_type <> 'ASSIGNED'
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO inventory_read_changed_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_assigned inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

WITH removed_legacy_scopes AS (
    DELETE FROM subject_role_permission_scopes srps
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srps.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
      AND srps.permission_id = p.id
      AND p.code = 'inventory:read'
      AND srps.scope_type <> 'ASSIGNED'
    RETURNING sra.subject_id
)
INSERT INTO inventory_read_changed_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_legacy_scopes
ON CONFLICT DO NOTHING;

WITH removed_stale_partitions AS (
    DELETE FROM subject_role_permission_partitions srpp
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srpp.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
      AND srpp.permission_id = p.id
      AND p.code = 'inventory:read'
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
INSERT INTO inventory_read_changed_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_stale_partitions
ON CONFLICT DO NOTHING;

WITH inserted_current_partitions AS (
    INSERT INTO subject_role_permission_partitions(
        assignment_id, permission_id, partition_type, partition_id
    )
    SELECT sra.id, p.id, 'BRANCH', au.branch_reference_id
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
        AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
    JOIN admin_users au ON au.authorization_subject_id = sra.subject_id
    JOIN permissions p ON p.code = 'inventory:read' AND p.active
    JOIN subject_role_permission_scopes srps
      ON srps.assignment_id = sra.id
     AND srps.permission_id = p.id
     AND srps.scope_type = 'ASSIGNED'
    WHERE sra.revoked_at IS NULL
      AND au.branch_reference_id IS NOT NULL
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO inventory_read_changed_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_current_partitions inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

-- One bump per repaired subject invalidates authorization caches after the
-- migration without conflating catalog-only changes with effective grants.
UPDATE authorization_subjects subject
SET authorization_version = authorization_version + 1,
    updated_at = now()
WHERE subject.id IN (
    SELECT changed.subject_id
    FROM inventory_read_changed_subjects changed
);

CREATE OR REPLACE FUNCTION sync_branch_inventory_read_assignment(
    target_assignment_id uuid,
    ensure_default_scope boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    inventory_subject_id uuid;
    assignment_revoked_at timestamptz;
    assignment_role_code varchar(64);
    inventory_permission_id uuid;
    inventory_branch_id uuid;
BEGIN
    SELECT sra.subject_id, sra.revoked_at, r.code
    INTO inventory_subject_id, assignment_revoked_at, assignment_role_code
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    WHERE sra.id = target_assignment_id;

    IF NOT FOUND OR assignment_role_code NOT IN ('MANAGER', 'RECEPTIONIST', 'STAFF') THEN
        RETURN;
    END IF;

    -- Serialize every inventory binding mutation for one subject. Without a
    -- transaction-scoped lock, an uncommitted partition INSERT can be invisible
    -- to a concurrent branch-change trigger and commit afterwards as a stale,
    -- cross-branch grant.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('inventory:read:' || inventory_subject_id::text, 0)
    );

    -- The assignment may have changed while waiting for the lock. Re-read the
    -- authoritative row before deciding which evidence is valid.
    SELECT sra.subject_id, sra.revoked_at, r.code
    INTO inventory_subject_id, assignment_revoked_at, assignment_role_code
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    WHERE sra.id = target_assignment_id;

    IF NOT FOUND OR assignment_role_code NOT IN ('MANAGER', 'RECEPTIONIST', 'STAFF') THEN
        RETURN;
    END IF;

    SELECT p.id
    INTO inventory_permission_id
    FROM permissions p
    WHERE p.code = 'inventory:read'
      AND p.active;

    IF inventory_permission_id IS NULL THEN
        RETURN;
    END IF;

    DELETE FROM subject_role_permission_scopes
    WHERE assignment_id = target_assignment_id
      AND permission_id = inventory_permission_id
      AND scope_type <> 'ASSIGNED';

    IF assignment_revoked_at IS NOT NULL THEN
        DELETE FROM subject_role_permission_partitions
        WHERE assignment_id = target_assignment_id
          AND permission_id = inventory_permission_id;
        RETURN;
    END IF;

    IF ensure_default_scope THEN
        INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
        VALUES (target_assignment_id, inventory_permission_id, 'ASSIGNED')
        ON CONFLICT DO NOTHING;
    END IF;

    -- Missing ASSIGNED means a deliberate reduction. Scope restoration is the
    -- only supported operation that may recreate the branch evidence.
    IF NOT EXISTS (
        SELECT 1
        FROM subject_role_permission_scopes srps
        WHERE srps.assignment_id = target_assignment_id
          AND srps.permission_id = inventory_permission_id
          AND srps.scope_type = 'ASSIGNED'
    ) THEN
        DELETE FROM subject_role_permission_partitions
        WHERE assignment_id = target_assignment_id
          AND permission_id = inventory_permission_id;
        RETURN;
    END IF;

    SELECT au.branch_reference_id
    INTO inventory_branch_id
    FROM admin_users au
    WHERE au.authorization_subject_id = inventory_subject_id;

    DELETE FROM subject_role_permission_partitions
    WHERE assignment_id = target_assignment_id
      AND permission_id = inventory_permission_id
      AND (
          partition_type <> 'BRANCH'
          OR inventory_branch_id IS NULL
          OR partition_id <> inventory_branch_id
      );

    IF inventory_branch_id IS NOT NULL THEN
        INSERT INTO subject_role_permission_partitions(
            assignment_id, permission_id, partition_type, partition_id
        )
        VALUES (target_assignment_id, inventory_permission_id, 'BRANCH', inventory_branch_id)
        ON CONFLICT DO NOTHING;
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION sync_branch_inventory_read_assignment_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    PERFORM sync_branch_inventory_read_assignment(NEW.id, TG_OP = 'INSERT');
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_branch_inventory_read_assignment_after_change
AFTER INSERT OR UPDATE OF revoked_at
ON subject_role_assignments
FOR EACH ROW
EXECUTE FUNCTION sync_branch_inventory_read_assignment_trigger();

CREATE OR REPLACE FUNCTION sync_branch_inventory_read_branch_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    inventory_assignment_id uuid;
    has_inventory_assignment boolean := false;
    manager_trigger_owns_version boolean := false;
BEGIN
    IF OLD.branch_reference_id IS NOT DISTINCT FROM NEW.branch_reference_id THEN
        RETURN NEW;
    END IF;

    FOR inventory_assignment_id IN
        SELECT sra.id
        FROM subject_role_assignments sra
        JOIN roles r ON r.id = sra.role_id
            AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
        WHERE sra.subject_id = NEW.authorization_subject_id
          AND sra.revoked_at IS NULL
    LOOP
        PERFORM sync_branch_inventory_read_assignment(inventory_assignment_id, false);
        IF EXISTS (
            SELECT 1
            FROM subject_role_permission_scopes srps
            JOIN permissions p ON p.id = srps.permission_id
                AND p.code = 'inventory:read'
            WHERE srps.assignment_id = inventory_assignment_id
              AND srps.scope_type = 'ASSIGNED'
        ) THEN
            has_inventory_assignment := true;
        END IF;
    END LOOP;

    -- V9 owns the branch-change cache bump whenever an active MANAGER role is
    -- present. V10 and this trigger only synchronize their own evidence, which
    -- keeps a supported branch move at exactly one authorization_version bump.
    SELECT EXISTS (
        SELECT 1
        FROM subject_role_assignments sra
        JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
        WHERE sra.subject_id = NEW.authorization_subject_id
          AND sra.revoked_at IS NULL
    ) INTO manager_trigger_owns_version;

    IF has_inventory_assignment AND NOT manager_trigger_owns_version THEN
        UPDATE authorization_subjects
        SET authorization_version = authorization_version + 1,
            updated_at = now()
        WHERE id = NEW.authorization_subject_id;
    END IF;

    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_branch_inventory_read_branch_after_change
AFTER UPDATE OF branch_reference_id
ON admin_users
FOR EACH ROW
EXECUTE FUNCTION sync_branch_inventory_read_branch_trigger();

CREATE OR REPLACE FUNCTION sync_branch_inventory_read_scope_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM sync_branch_inventory_read_assignment(OLD.assignment_id, false);
        RETURN OLD;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.assignment_id IS DISTINCT FROM NEW.assignment_id THEN
        PERFORM sync_branch_inventory_read_assignment(OLD.assignment_id, false);
    END IF;

    PERFORM sync_branch_inventory_read_assignment(NEW.assignment_id, false);
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_branch_inventory_read_scope_after_insert
AFTER INSERT
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_branch_inventory_read_scope_trigger();

CREATE TRIGGER sync_branch_inventory_read_scope_after_update
AFTER UPDATE OF assignment_id, permission_id, scope_type
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_branch_inventory_read_scope_trigger();

CREATE TRIGGER sync_branch_inventory_read_scope_after_delete
AFTER DELETE
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_branch_inventory_read_scope_trigger();

-- Database guards close direct-SQL and future code paths that would otherwise
-- bypass the branch-only inventory boundary.
CREATE OR REPLACE FUNCTION reject_branch_inventory_read_scope_policy_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF NEW.scope_type <> 'ASSIGNED' AND EXISTS (
        SELECT 1
        FROM roles r, permissions p
        WHERE r.id = NEW.role_id
          AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
          AND p.id = NEW.permission_id
          AND p.code = 'inventory:read'
    ) THEN
        RAISE EXCEPTION 'Branch operational inventory:read policy must use ASSIGNED'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_branch_inventory_read_scope_policy
BEFORE INSERT OR UPDATE OF role_id, permission_id, scope_type
ON role_permission_policies
FOR EACH ROW
EXECUTE FUNCTION reject_branch_inventory_read_scope_policy_trigger();

CREATE OR REPLACE FUNCTION reject_branch_inventory_read_partition_policy_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF NEW.partition_type <> 'BRANCH' AND EXISTS (
        SELECT 1
        FROM roles r, permissions p
        WHERE r.id = NEW.role_id
          AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
          AND p.id = NEW.permission_id
          AND p.code = 'inventory:read'
    ) THEN
        RAISE EXCEPTION 'Branch operational inventory:read partition policy must use BRANCH'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_branch_inventory_read_partition_policy
BEFORE INSERT OR UPDATE OF role_id, permission_id, partition_type
ON role_permission_partition_policies
FOR EACH ROW
EXECUTE FUNCTION reject_branch_inventory_read_partition_policy_trigger();

CREATE OR REPLACE FUNCTION reject_branch_inventory_read_subject_scope_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF NEW.scope_type <> 'ASSIGNED' AND EXISTS (
        SELECT 1
        FROM subject_role_assignments sra
        JOIN roles r ON r.id = sra.role_id
        JOIN permissions p ON p.id = NEW.permission_id
        WHERE sra.id = NEW.assignment_id
          AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
          AND p.code = 'inventory:read'
    ) THEN
        RAISE EXCEPTION 'Branch operational assignment cannot receive inventory:read outside ASSIGNED'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_branch_inventory_read_subject_scope
BEFORE INSERT OR UPDATE OF assignment_id, permission_id, scope_type
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION reject_branch_inventory_read_subject_scope_trigger();

CREATE OR REPLACE FUNCTION reject_invalid_branch_inventory_read_partition_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    inventory_subject_id uuid;
    inventory_assignment_revoked_at timestamptz;
    current_inventory_branch_id uuid;
BEGIN
    SELECT sra.subject_id
    INTO inventory_subject_id
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
        AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
    JOIN permissions p ON p.id = NEW.permission_id AND p.code = 'inventory:read'
    WHERE sra.id = NEW.assignment_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('inventory:read:' || inventory_subject_id::text, 0)
    );

    SELECT sra.subject_id, sra.revoked_at, au.branch_reference_id
    INTO inventory_subject_id, inventory_assignment_revoked_at,
         current_inventory_branch_id
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
        AND r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')
    JOIN permissions p ON p.id = NEW.permission_id AND p.code = 'inventory:read'
    LEFT JOIN admin_users au ON au.authorization_subject_id = sra.subject_id
    WHERE sra.id = NEW.assignment_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF inventory_assignment_revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'Revoked branch assignment cannot receive an inventory:read partition'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.partition_type <> 'BRANCH'
       OR current_inventory_branch_id IS NULL
       OR NEW.partition_id <> current_inventory_branch_id THEN
        RAISE EXCEPTION 'Operational inventory:read partition must match the current BRANCH'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM subject_role_permission_scopes srps
        WHERE srps.assignment_id = NEW.assignment_id
          AND srps.permission_id = NEW.permission_id
          AND srps.scope_type = 'ASSIGNED'
    ) THEN
        RAISE EXCEPTION 'Operational inventory:read partition requires an ASSIGNED scope'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_invalid_branch_inventory_read_partition
BEFORE INSERT OR UPDATE OF assignment_id, permission_id, partition_type, partition_id
ON subject_role_permission_partitions
FOR EACH ROW
EXECUTE FUNCTION reject_invalid_branch_inventory_read_partition_trigger();

-- A role assignment is an audited identity, not a mutable container. Moving an
-- existing row to another subject or role would carry all of its scopes and
-- partitions with it and could bypass every permission-specific guard.
CREATE OR REPLACE FUNCTION reject_subject_role_assignment_identity_change_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF OLD.subject_id IS DISTINCT FROM NEW.subject_id
       OR OLD.role_id IS DISTINCT FROM NEW.role_id THEN
        RAISE EXCEPTION 'Role assignment subject and role are immutable; revoke and create a new assignment'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_subject_role_assignment_identity_change
BEFORE UPDATE OF subject_id, role_id
ON subject_role_assignments
FOR EACH ROW
EXECUTE FUNCTION reject_subject_role_assignment_identity_change_trigger();
