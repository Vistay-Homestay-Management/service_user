SET search_path TO app, extensions, public;

-- Creating and releasing an inventory block is a privileged Backoffice write.
-- SUPER_ADMIN may operate globally. MANAGER may operate only inside the
-- current branch recorded on the admin profile. Missing MANAGER scope rows are
-- deliberate reductions and must not be recreated during migration or later
-- lifecycle synchronization.
CREATE TEMP TABLE inventory_block_changed_subjects (
    subject_id uuid PRIMARY KEY
) ON COMMIT DROP;

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

-- Normalize an existing effective SUPER_ADMIN grant to its only valid scope.
-- A missing row remains missing so an explicit reduction is not undone.
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
INSERT INTO inventory_block_changed_subjects(subject_id)
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
INSERT INTO inventory_block_changed_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_super_non_all
ON CONFLICT DO NOTHING;

-- Any existing MANAGER scope still represents an effective grant. Narrow it
-- to ASSIGNED; do not synthesize a grant for an assignment with no row.
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
INSERT INTO inventory_block_changed_subjects(subject_id)
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
INSERT INTO inventory_block_changed_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_manager_non_assigned
ON CONFLICT DO NOTHING;

-- Scrub any legacy or direct-SQL grant carried by a role that is not allowed
-- to mutate inventory. Subject scope rows do not reference role_permissions,
-- so both evidence tables must be cleaned explicitly before catalog cleanup.
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
INSERT INTO inventory_block_changed_subjects(subject_id)
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
INSERT INTO inventory_block_changed_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_forbidden_scopes
ON CONFLICT DO NOTHING;

-- SUPER_ADMIN uses ALL and therefore never carries partition evidence.
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
INSERT INTO inventory_block_changed_subjects(subject_id)
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
INSERT INTO inventory_block_changed_subjects(subject_id)
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
INSERT INTO inventory_block_changed_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_current_manager_partitions inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

UPDATE authorization_subjects subject
SET authorization_version = authorization_version + 1,
    updated_at = now()
WHERE subject.id IN (
    SELECT changed.subject_id
    FROM inventory_block_changed_subjects changed
);

CREATE OR REPLACE FUNCTION sync_manager_inventory_block_assignment(
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

    IF NOT FOUND OR assignment_role_code <> 'MANAGER' THEN
        RETURN;
    END IF;

    -- Serialize block evidence with branch movement. Otherwise an uncommitted
    -- partition write can be invisible to the branch trigger and commit later
    -- as a stale cross-branch grant.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('inventory:block:' || inventory_subject_id::text, 0)
    );

    SELECT sra.subject_id, sra.revoked_at, r.code
    INTO inventory_subject_id, assignment_revoked_at, assignment_role_code
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    WHERE sra.id = target_assignment_id;

    IF NOT FOUND OR assignment_role_code <> 'MANAGER' THEN
        RETURN;
    END IF;

    SELECT p.id
    INTO inventory_permission_id
    FROM permissions p
    WHERE p.code = 'inventory:block'
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

CREATE OR REPLACE FUNCTION sync_manager_inventory_block_assignment_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    PERFORM sync_manager_inventory_block_assignment(NEW.id, TG_OP = 'INSERT');
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_inventory_block_assignment_after_change
AFTER INSERT OR UPDATE OF revoked_at
ON subject_role_assignments
FOR EACH ROW
EXECUTE FUNCTION sync_manager_inventory_block_assignment_trigger();

CREATE OR REPLACE FUNCTION sync_manager_inventory_block_branch_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    inventory_assignment_id uuid;
BEGIN
    IF OLD.branch_reference_id IS NOT DISTINCT FROM NEW.branch_reference_id THEN
        RETURN NEW;
    END IF;

    FOR inventory_assignment_id IN
        SELECT sra.id
        FROM subject_role_assignments sra
        JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
        WHERE sra.subject_id = NEW.authorization_subject_id
          AND sra.revoked_at IS NULL
    LOOP
        PERFORM sync_manager_inventory_block_assignment(inventory_assignment_id, false);
    END LOOP;

    -- V9 owns the single authorization_version bump for every active MANAGER
    -- branch move. V10, V11, and this trigger synchronize only their evidence.
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_inventory_block_branch_after_change
AFTER UPDATE OF branch_reference_id
ON admin_users
FOR EACH ROW
EXECUTE FUNCTION sync_manager_inventory_block_branch_trigger();

CREATE OR REPLACE FUNCTION sync_manager_inventory_block_scope_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM sync_manager_inventory_block_assignment(OLD.assignment_id, false);
        RETURN OLD;
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.assignment_id IS DISTINCT FROM NEW.assignment_id THEN
        PERFORM sync_manager_inventory_block_assignment(OLD.assignment_id, false);
    END IF;

    PERFORM sync_manager_inventory_block_assignment(NEW.assignment_id, false);
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_inventory_block_scope_after_insert
AFTER INSERT
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_manager_inventory_block_scope_trigger();

CREATE TRIGGER sync_manager_inventory_block_scope_after_update
AFTER UPDATE OF assignment_id, permission_id, scope_type
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_manager_inventory_block_scope_trigger();

CREATE TRIGGER sync_manager_inventory_block_scope_after_delete
AFTER DELETE
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_manager_inventory_block_scope_trigger();

-- Direct-SQL guards keep the checked-in catalog and subject evidence at the
-- same maximum authority as the application workflow.
CREATE OR REPLACE FUNCTION reject_invalid_inventory_block_role_permission_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM permissions p
        JOIN roles r ON r.id = NEW.role_id
        WHERE p.id = NEW.permission_id
          AND p.code = 'inventory:block'
          AND r.code NOT IN ('SUPER_ADMIN', 'MANAGER')
    ) THEN
        RAISE EXCEPTION 'inventory:block is limited to SUPER_ADMIN and MANAGER'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_invalid_inventory_block_role_permission
BEFORE INSERT OR UPDATE OF role_id, permission_id
ON role_permissions
FOR EACH ROW
EXECUTE FUNCTION reject_invalid_inventory_block_role_permission_trigger();

CREATE OR REPLACE FUNCTION reject_invalid_inventory_block_scope_policy_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    inventory_role_code varchar(64);
BEGIN
    SELECT r.code
    INTO inventory_role_code
    FROM roles r
    JOIN permissions p ON p.id = NEW.permission_id AND p.code = 'inventory:block'
    WHERE r.id = NEW.role_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF (inventory_role_code = 'SUPER_ADMIN' AND NEW.scope_type <> 'ALL')
       OR (inventory_role_code = 'MANAGER' AND NEW.scope_type <> 'ASSIGNED')
       OR inventory_role_code NOT IN ('SUPER_ADMIN', 'MANAGER') THEN
        RAISE EXCEPTION 'Invalid inventory:block role scope policy for %', inventory_role_code
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_invalid_inventory_block_scope_policy
BEFORE INSERT OR UPDATE OF role_id, permission_id, scope_type
ON role_permission_policies
FOR EACH ROW
EXECUTE FUNCTION reject_invalid_inventory_block_scope_policy_trigger();

CREATE OR REPLACE FUNCTION reject_invalid_inventory_block_partition_policy_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    inventory_role_code varchar(64);
BEGIN
    SELECT r.code
    INTO inventory_role_code
    FROM roles r
    JOIN permissions p ON p.id = NEW.permission_id AND p.code = 'inventory:block'
    WHERE r.id = NEW.role_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF inventory_role_code <> 'MANAGER' OR NEW.partition_type <> 'BRANCH' THEN
        RAISE EXCEPTION 'inventory:block partition policy must be MANAGER BRANCH'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_invalid_inventory_block_partition_policy
BEFORE INSERT OR UPDATE OF role_id, permission_id, partition_type
ON role_permission_partition_policies
FOR EACH ROW
EXECUTE FUNCTION reject_invalid_inventory_block_partition_policy_trigger();

CREATE OR REPLACE FUNCTION reject_invalid_inventory_block_subject_scope_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    inventory_role_code varchar(64);
BEGIN
    SELECT r.code
    INTO inventory_role_code
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    JOIN permissions p ON p.id = NEW.permission_id AND p.code = 'inventory:block'
    WHERE sra.id = NEW.assignment_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF (inventory_role_code = 'SUPER_ADMIN' AND NEW.scope_type <> 'ALL')
       OR (inventory_role_code = 'MANAGER' AND NEW.scope_type <> 'ASSIGNED')
       OR inventory_role_code NOT IN ('SUPER_ADMIN', 'MANAGER') THEN
        RAISE EXCEPTION 'Invalid inventory:block assignment scope for %', inventory_role_code
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_invalid_inventory_block_subject_scope
BEFORE INSERT OR UPDATE OF assignment_id, permission_id, scope_type
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION reject_invalid_inventory_block_subject_scope_trigger();

CREATE OR REPLACE FUNCTION reject_invalid_manager_inventory_block_partition_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    inventory_subject_id uuid;
    inventory_role_code varchar(64);
    inventory_assignment_revoked_at timestamptz;
    current_inventory_branch_id uuid;
BEGIN
    SELECT sra.subject_id, r.code
    INTO inventory_subject_id, inventory_role_code
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    JOIN permissions p ON p.id = NEW.permission_id AND p.code = 'inventory:block'
    WHERE sra.id = NEW.assignment_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF inventory_role_code <> 'MANAGER' THEN
        RAISE EXCEPTION 'Only MANAGER may carry an inventory:block partition'
            USING ERRCODE = '23514';
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('inventory:block:' || inventory_subject_id::text, 0)
    );

    SELECT sra.subject_id, r.code, sra.revoked_at, au.branch_reference_id
    INTO inventory_subject_id, inventory_role_code,
         inventory_assignment_revoked_at, current_inventory_branch_id
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id
    JOIN permissions p ON p.id = NEW.permission_id AND p.code = 'inventory:block'
    LEFT JOIN admin_users au ON au.authorization_subject_id = sra.subject_id
    WHERE sra.id = NEW.assignment_id;

    IF NOT FOUND OR inventory_role_code <> 'MANAGER' THEN
        RAISE EXCEPTION 'Only MANAGER may carry an inventory:block partition'
            USING ERRCODE = '23514';
    END IF;

    IF inventory_assignment_revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'Revoked MANAGER assignment cannot receive an inventory:block partition'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.partition_type <> 'BRANCH'
       OR current_inventory_branch_id IS NULL
       OR NEW.partition_id <> current_inventory_branch_id THEN
        RAISE EXCEPTION 'MANAGER inventory:block partition must match the current BRANCH'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM subject_role_permission_scopes srps
        WHERE srps.assignment_id = NEW.assignment_id
          AND srps.permission_id = NEW.permission_id
          AND srps.scope_type = 'ASSIGNED'
    ) THEN
        RAISE EXCEPTION 'MANAGER inventory:block partition requires an ASSIGNED scope'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_invalid_manager_inventory_block_partition
BEFORE INSERT OR UPDATE OF assignment_id, permission_id, partition_type, partition_id
ON subject_role_permission_partitions
FOR EACH ROW
EXECUTE FUNCTION reject_invalid_manager_inventory_block_partition_trigger();
