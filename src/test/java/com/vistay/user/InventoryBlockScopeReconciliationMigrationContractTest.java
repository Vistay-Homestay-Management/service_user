package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class InventoryBlockScopeReconciliationMigrationContractTest {

    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V13__reconcile_inventory_block_scope.sql");

    @Test
    void locksTheWholeAuthorizationWriteSetBeforeReconciliation() throws Exception {
        var sql = Files.readString(MIGRATION);
        var lock = sql.indexOf("LOCK TABLE");
        var firstBackfill = sql.indexOf("CREATE TEMP TABLE");

        assertThat(lock).isGreaterThanOrEqualTo(0);
        assertThat(firstBackfill).isGreaterThan(lock);
        assertThat(sql)
            .contains("roles,")
            .contains("permissions,")
            .contains("authorization_partition_types,")
            .contains("role_permissions,")
            .contains("role_permission_policies,")
            .contains("role_permission_partition_policies,")
            .contains("authorization_subjects,")
            .contains("admin_users,")
            .contains("subject_role_assignments,")
            .contains("subject_role_permission_scopes,")
            .contains("subject_role_permission_partitions")
            .contains("IN EXCLUSIVE MODE NOWAIT")
            .contains("p.code = 'inventory:block'")
            .contains("r.code IN ('SUPER_ADMIN', 'MANAGER')")
            .contains("r.code NOT IN ('SUPER_ADMIN', 'MANAGER')")
            .contains("removed_stale_manager_partitions")
            .contains("inserted_current_manager_partitions")
            .contains("inventory_block_reconciled_subjects")
            .contains("authorization_version = authorization_version + 1");
    }
}
