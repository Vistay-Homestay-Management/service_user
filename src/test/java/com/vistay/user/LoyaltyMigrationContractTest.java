package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class LoyaltyMigrationContractTest {
    @Test
    void definesVersionedMakerCheckerProgramAndAppendOnlyPointLedger() throws Exception {
        var sql = Files.readString(Path.of("src/main/resources/db/migration/V14_2__loyalty_programs_and_ledger.sql"));
        var invariants = Files.readString(Path.of("src/main/resources/db/migration/V14_3__loyalty_projection_invariants.sql"));
        var analytics = Files.readString(Path.of("src/main/resources/db/migration/V14_4__analytics_permission.sql"));
        assertThat(sql).contains("loyalty_program_versions", "loyalty_tier_bands",
            "loyalty_earning_rules", "loyalty_point_ledger", "customer_loyalty_projections",
            "approved_by_subject_id <> requested_by_subject_id", "expected_program_version");
        assertThat(invariants).contains("BEFORE UPDATE OR DELETE ON loyalty_point_ledger",
            "published loyalty tiers are immutable");
        assertThat(analytics).contains("analytics', 'read'", "SUPER_ADMIN", "'ALL'");
    }
}
