package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class AuthorizationV2MigrationContractTest {
    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V14_1__authorization_v2_role_policies.sql");

    @Test
    void versionsRolePolicyMakerCheckerAndProtectedRoleInvariants() throws Exception {
        var sql = Files.readString(MIGRATION);
        assertThat(sql)
            .contains("policy_version bigint NOT NULL DEFAULT 1")
            .contains("role_policy_change_requests")
            .contains("CREATE_ROLE", "CHANGE_PERMISSIONS", "DEACTIVATE_ROLE")
            .contains("UNIQUE (requested_by_subject_id, idempotency_key)")
            .contains("protect_system_role_identity")
            .contains("system roles cannot be deleted")
            .contains("role_permission_partition_types")
            .contains("booking-sensitive', 'read")
            .contains("notification-template', 'publish")
            .contains("notification-delivery', 'retry");
    }
}
