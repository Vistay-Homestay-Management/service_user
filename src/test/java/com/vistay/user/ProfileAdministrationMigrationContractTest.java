package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ProfileAdministrationMigrationContractTest {
    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V18__profile_administration_and_registration_policy.sql");

    @Test
    void keepsProfileCreationReplaySafeAndRegistrationPolicyTypeSpecific() throws Exception {
        var sql = Files.readString(MIGRATION);
        assertThat(sql)
            .contains("registration_enabled boolean NOT NULL DEFAULT true")
            .contains("SET registration_enabled = account_type <> 'ADMIN'")
            .contains("profile_creation_requests")
            .contains("idempotency_key varchar(160) PRIMARY KEY")
            .contains("customer-profile', 'create'")
            .contains("admin-profile', 'create'")
            .contains("host-profile', 'create'")
            .contains("customer-account', 'provision'")
            .contains("host-account', 'provision'")
            .contains("admin-account', 'provision'")
            .contains("identity-policy', 'read'")
            .contains("identity-policy', 'update'");
    }
}
