package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class InventoryBlockScopeMigrationContractTest {

    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V12__restrict_manager_inventory_block_scope.sql");

    @Test
    void versionsTheManagerInventoryBlockBoundaryAndDatabaseGuards() throws Exception {
        var sql = Files.readString(MIGRATION);

        assertThat(sql)
            .contains("p.code = 'inventory:block'")
            .contains("r.code IN ('SUPER_ADMIN', 'MANAGER')")
            .contains("r.code NOT IN ('SUPER_ADMIN', 'MANAGER')")
            .contains("r.code = 'SUPER_ADMIN' AND rpp.scope_type <> 'ALL'")
            .contains("r.code = 'MANAGER' AND rpp.scope_type <> 'ASSIGNED'")
            .contains("'BRANCH', au.branch_reference_id")
            .contains("sync_manager_inventory_block_assignment")
            .contains("AFTER INSERT OR UPDATE OF revoked_at")
            .contains("AFTER UPDATE OF branch_reference_id")
            .contains("sync_manager_inventory_block_scope_after_insert")
            .contains("sync_manager_inventory_block_scope_after_update")
            .contains("sync_manager_inventory_block_scope_after_delete")
            .contains("reject_invalid_inventory_block_role_permission")
            .contains("reject_invalid_inventory_block_scope_policy")
            .contains("reject_invalid_inventory_block_partition_policy")
            .contains("reject_invalid_inventory_block_subject_scope")
            .contains("reject_invalid_manager_inventory_block_partition")
            .contains("BEFORE INSERT OR UPDATE OF assignment_id, permission_id, partition_type, partition_id")
            .contains("MANAGER inventory:block partition must match the current BRANCH")
            .contains("MANAGER inventory:block partition requires an ASSIGNED scope")
            .contains("pg_advisory_xact_lock")
            .contains("hashtextextended('inventory:block:' || inventory_subject_id::text, 0)")
            .contains("V9 owns the single authorization_version bump");
    }
}
