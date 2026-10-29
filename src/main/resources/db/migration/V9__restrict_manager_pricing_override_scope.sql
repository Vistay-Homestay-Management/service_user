SET search_path TO app, extensions, public;

-- V8 briefly declared ALL as an optional MANAGER scope. Pricing overrides are
-- intentionally branch-bound for managers, so remove that escalation path and
-- defensively revoke any ALL grant issued before this corrective migration.
CREATE TEMP TABLE manager_pricing_override_changed_subjects (
    subject_id uuid PRIMARY KEY
) ON COMMIT DROP;

WITH removed_manager_all AS (
    DELETE FROM subject_role_permission_scopes srps
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srps.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code = 'MANAGER'
      AND srps.permission_id = p.id
      AND p.code = 'pricing:override'
      AND srps.scope_type = 'ALL'
    RETURNING sra.subject_id
)
INSERT INTO manager_pricing_override_changed_subjects(subject_id)
SELECT DISTINCT subject_id FROM removed_manager_all
ON CONFLICT DO NOTHING;

DELETE FROM role_permission_policies rpp
USING roles r, permissions p
WHERE rpp.role_id = r.id
  AND r.code = 'MANAGER'
  AND rpp.permission_id = p.id
  AND p.code = 'pricing:override'
  AND rpp.scope_type = 'ALL';

-- Repair any assignment that did not receive the V8 default scope and make
-- existing partition bindings exact before enabling the forward-only hooks.
WITH inserted_manager_assigned AS (
    INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
    SELECT sra.id, p.id, 'ASSIGNED'
    FROM subject_role_assignments sra
    JOIN roles r ON r.id = sra.role_id AND r.code = 'MANAGER'
    JOIN permissions p ON p.code = 'pricing:override' AND p.active
    WHERE sra.revoked_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO manager_pricing_override_changed_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_manager_assigned inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

WITH removed_stale_partitions AS (
    DELETE FROM subject_role_permission_partitions srpp
    USING subject_role_assignments sra, roles r, permissions p
    WHERE srpp.assignment_id = sra.id
      AND sra.role_id = r.id
      AND r.code = 'MANAGER'
      AND srpp.permission_id = p.id
      AND p.code = 'pricing:override'
      AND (
          sra.revoked_at IS NOT NULL
          OR srpp.partition_type <> 'BRANCH'
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
INSERT INTO manager_pricing_override_changed_subjects(subject_id)
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
    JOIN permissions p ON p.code = 'pricing:override' AND p.active
    WHERE sra.revoked_at IS NULL
      AND au.branch_reference_id IS NOT NULL
    ON CONFLICT DO NOTHING
    RETURNING assignment_id
)
INSERT INTO manager_pricing_override_changed_subjects(subject_id)
SELECT DISTINCT sra.subject_id
FROM inserted_current_partitions inserted
JOIN subject_role_assignments sra ON sra.id = inserted.assignment_id
ON CONFLICT DO NOTHING;

UPDATE authorization_subjects subject
SET authorization_version = authorization_version + 1,
    updated_at = now()
WHERE subject.id IN (
    SELECT changed.subject_id
    FROM manager_pricing_override_changed_subjects changed
);

-- Keep one active MANAGER assignment synchronized with the current branch.
-- The assignment scope remains for audit after revocation, while its partition
-- binding is removed so no stale domain reference survives the role lifecycle.
CREATE OR REPLACE FUNCTION sync_manager_pricing_override_assignment(
    target_assignment_id uuid,
    ensure_default_scope boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    manager_subject_id uuid;
    assignment_revoked_at timestamptz;
    assignment_role_code varchar(64);
    override_permission_id uuid;
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

    SELECT p.id
    INTO override_permission_id
    FROM permissions p
    WHERE p.code = 'pricing:override'
      AND p.active;

    IF override_permission_id IS NULL THEN
        RETURN;
    END IF;

    DELETE FROM subject_role_permission_scopes
    WHERE assignment_id = target_assignment_id
      AND permission_id = override_permission_id
      AND scope_type = 'ALL';

    IF assignment_revoked_at IS NOT NULL THEN
        DELETE FROM subject_role_permission_partitions
        WHERE assignment_id = target_assignment_id
          AND permission_id = override_permission_id;
        RETURN;
    END IF;

    IF ensure_default_scope THEN
        INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
        VALUES (target_assignment_id, override_permission_id, 'ASSIGNED')
        ON CONFLICT DO NOTHING;
    END IF;

    -- A deliberate scope reduction may remove this permission while leaving
    -- the MANAGER role active. Do not recreate or retain a branch binding in
    -- that case; a later branch reassignment must not silently restore access.
    IF NOT EXISTS (
        SELECT 1
        FROM subject_role_permission_scopes srps
        WHERE srps.assignment_id = target_assignment_id
          AND srps.permission_id = override_permission_id
          AND srps.scope_type = 'ASSIGNED'
    ) THEN
        DELETE FROM subject_role_permission_partitions
        WHERE assignment_id = target_assignment_id
          AND permission_id = override_permission_id;
        RETURN;
    END IF;

    SELECT au.branch_reference_id
    INTO manager_branch_id
    FROM admin_users au
    WHERE au.authorization_subject_id = manager_subject_id;

    DELETE FROM subject_role_permission_partitions
    WHERE assignment_id = target_assignment_id
      AND permission_id = override_permission_id
      AND (
          partition_type <> 'BRANCH'
          OR manager_branch_id IS NULL
          OR partition_id <> manager_branch_id
      );

    IF manager_branch_id IS NOT NULL THEN
        INSERT INTO subject_role_permission_partitions(
            assignment_id, permission_id, partition_type, partition_id
        )
        VALUES (target_assignment_id, override_permission_id, 'BRANCH', manager_branch_id)
        ON CONFLICT DO NOTHING;
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION sync_manager_pricing_override_assignment_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    PERFORM sync_manager_pricing_override_assignment(NEW.id, TG_OP = 'INSERT');
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_pricing_override_assignment_after_change
AFTER INSERT OR UPDATE OF revoked_at
ON subject_role_assignments
FOR EACH ROW
EXECUTE FUNCTION sync_manager_pricing_override_assignment_trigger();

CREATE OR REPLACE FUNCTION sync_manager_pricing_override_branch_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
DECLARE
    manager_assignment_id uuid;
    has_manager_assignment boolean := false;
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
        has_manager_assignment := true;
        PERFORM sync_manager_pricing_override_assignment(manager_assignment_id, false);
    END LOOP;

    IF has_manager_assignment THEN
        UPDATE authorization_subjects
        SET authorization_version = authorization_version + 1,
            updated_at = now()
        WHERE id = NEW.authorization_subject_id;
    END IF;

    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_pricing_override_branch_after_change
AFTER UPDATE OF branch_reference_id
ON admin_users
FOR EACH ROW
EXECUTE FUNCTION sync_manager_pricing_override_branch_trigger();

-- Keep partition evidence aligned when maker-checker scope reduction removes
-- or later restores the pricing override grant on an active MANAGER role.
CREATE OR REPLACE FUNCTION sync_manager_pricing_override_scope_trigger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO app, extensions, public
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM sync_manager_pricing_override_assignment(OLD.assignment_id, false);
        RETURN OLD;
    END IF;
    PERFORM sync_manager_pricing_override_assignment(NEW.assignment_id, false);
    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_manager_pricing_override_scope_after_insert
AFTER INSERT
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_manager_pricing_override_scope_trigger();

CREATE TRIGGER sync_manager_pricing_override_scope_after_delete
AFTER DELETE
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION sync_manager_pricing_override_scope_trigger();

-- Policy and assignment guards make MANAGER@ALL impossible even if a future
-- code path bypasses AuthorizationManagementService validation.
CREATE OR REPLACE FUNCTION reject_manager_pricing_override_all_policy_trigger()
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
          AND p.code = 'pricing:override'
    ) THEN
        RAISE EXCEPTION 'MANAGER cannot use pricing:override@ALL policy'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_manager_pricing_override_all_policy
BEFORE INSERT OR UPDATE OF role_id, permission_id, scope_type
ON role_permission_policies
FOR EACH ROW
EXECUTE FUNCTION reject_manager_pricing_override_all_policy_trigger();

CREATE OR REPLACE FUNCTION reject_manager_pricing_override_all_scope_trigger()
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
          AND p.code = 'pricing:override'
    ) THEN
        RAISE EXCEPTION 'MANAGER cannot receive pricing:override@ALL'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER reject_manager_pricing_override_all_scope
BEFORE INSERT OR UPDATE OF assignment_id, permission_id, scope_type
ON subject_role_permission_scopes
FOR EACH ROW
EXECUTE FUNCTION reject_manager_pricing_override_all_scope_trigger();
