package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class PricingManagementScopeMigrationContractTest {

    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V10__restrict_manager_pricing_management_scope.sql");

    @Test
    void versionsTheManagerBranchBoundaryAndDatabaseGuards() throws Exception {
        var sql = Files.readString(MIGRATION);

        assertThat(sql)
            .contains("p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')")
            .contains("r.code = 'MANAGER'")
            .contains("r.code = 'SUPER_ADMIN'")
            .contains("'BRANCH', au.branch_reference_id")
            .contains("sync_manager_pricing_management_assignment")
            .contains("AFTER INSERT OR UPDATE OF revoked_at")
            .contains("AFTER UPDATE OF branch_reference_id")
            .contains("sync_manager_pricing_management_scope_after_insert")
            .contains("sync_manager_pricing_management_scope_after_delete")
            .contains("reject_manager_pricing_management_all_policy")
            .contains("reject_manager_pricing_management_all_scope")
            .contains("reject_invalid_manager_pricing_management_partition")
            .contains("BEFORE INSERT OR UPDATE OF assignment_id, permission_id, partition_type, partition_id")
            .contains("MANAGER pricing partition must match the current BRANCH")
            .contains("MANAGER pricing partition requires an ASSIGNED scope")
            .contains("MANAGER cannot use branch-bound pricing permissions at ALL policy")
            .contains("MANAGER cannot receive branch-bound pricing permission at ALL");
    }
}
