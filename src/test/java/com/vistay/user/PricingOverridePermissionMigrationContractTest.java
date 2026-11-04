package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class PricingOverridePermissionMigrationContractTest {

    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V8__pricing_override_permissions.sql");
    private static final Path RESTRICTION = Path.of(
        "src/main/resources/db/migration/V9__restrict_manager_pricing_override_scope.sql");

    @Test
    void keepsTheExactPricingOverridePermissionCodesAndRoleBoundaryVersioned() throws Exception {
        var sql = Files.readString(MIGRATION);
        var restriction = Files.readString(RESTRICTION);

        assertThat(sql)
            .contains("('pricing', 'override'")
            .contains("('pricing', 'approve-large-override'")
            .contains("r.code = 'SUPER_ADMIN'")
            .contains("r.code = 'MANAGER'")
            .contains("p.code = 'pricing:override'")
            .contains("p.code IN ('pricing:override', 'pricing:approve-large-override')")
            .contains("scope.scope_type = 'ASSIGNED'")
            .contains("'BRANCH', au.branch_reference_id");
        assertThat(restriction)
            .contains("r.code = 'MANAGER'")
            .contains("p.code = 'pricing:override'")
            .contains("srps.scope_type = 'ALL'")
            .contains("rpp.scope_type = 'ALL'")
            .contains("sync_manager_pricing_override_assignment")
            .contains("AFTER INSERT OR UPDATE OF revoked_at")
            .contains("AFTER UPDATE OF branch_reference_id")
            .contains("authorization_version = authorization_version + 1")
            .contains("reject_manager_pricing_override_all_policy")
            .contains("reject_manager_pricing_override_all_scope")
            .contains("MANAGER cannot receive pricing:override@ALL");
    }
}
