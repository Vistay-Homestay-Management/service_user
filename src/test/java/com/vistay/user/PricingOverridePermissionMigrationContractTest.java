package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class PricingOverridePermissionMigrationContractTest {

    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V8__pricing_override_permissions.sql");

    @Test
    void keepsTheExactPricingOverridePermissionCodesAndRoleBoundaryVersioned() throws Exception {
        var sql = Files.readString(MIGRATION);

        assertThat(sql)
            .contains("('pricing', 'override'")
            .contains("('pricing', 'approve-large-override'")
            .contains("r.code = 'SUPER_ADMIN'")
            .contains("r.code = 'MANAGER'")
            .contains("p.code = 'pricing:override'")
            .contains("p.code IN ('pricing:override', 'pricing:approve-large-override')")
            .contains("scope.scope_type = 'ASSIGNED'")
            .contains("'BRANCH', au.branch_reference_id");
    }
}
