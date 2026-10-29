package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class InventoryReadScopeMigrationContractTest {

    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V11__restrict_inventory_read_scope.sql");

    @Test
    void versionsTheInventoryBranchBoundaryAndDatabaseGuards() throws Exception {
        var sql = Files.readString(MIGRATION);

        assertThat(sql)
            .contains("p.code = 'inventory:read'")
            .contains("r.code IN ('SUPER_ADMIN', 'CTV')")
            .contains("r.code IN ('MANAGER', 'RECEPTIONIST', 'STAFF')")
            .contains("'BRANCH', au.branch_reference_id")
            .contains("sync_branch_inventory_read_assignment")
            .contains("AFTER INSERT OR UPDATE OF revoked_at")
            .contains("AFTER UPDATE OF branch_reference_id")
            .contains("sync_branch_inventory_read_scope_after_insert")
            .contains("sync_branch_inventory_read_scope_after_update")
            .contains("sync_branch_inventory_read_scope_after_delete")
            .contains("reject_branch_inventory_read_scope_policy")
            .contains("reject_branch_inventory_read_partition_policy")
            .contains("reject_branch_inventory_read_subject_scope")
            .contains("reject_invalid_branch_inventory_read_partition")
            .contains("BEFORE INSERT OR UPDATE OF assignment_id, permission_id, partition_type, partition_id")
            .contains("Operational inventory:read partition must match the current BRANCH")
            .contains("Operational inventory:read partition requires an ASSIGNED scope")
            .contains("pg_advisory_xact_lock")
            .contains("hashtextextended('inventory:read:' || inventory_subject_id::text, 0)")
            .contains("reject_subject_role_assignment_identity_change")
            .contains("BEFORE UPDATE OF subject_id, role_id")
            .contains("manager_trigger_owns_version")
            .contains("V9 owns the branch-change cache bump");
    }
}
