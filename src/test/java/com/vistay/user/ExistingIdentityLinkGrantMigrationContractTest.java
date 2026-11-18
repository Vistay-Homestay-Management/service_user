package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ExistingIdentityLinkGrantMigrationContractTest {
    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V22__reconcile_existing_identity_link_grants.sql");

    @Test
    void projectsIdentityLinkManagementToExistingProtectedAdminAssignments() throws Exception {
        var sql = Files.readString(MIGRATION);

        assertThat(sql)
            .contains("'identity-document:manage'")
            .contains("'identity-link:read'")
            .contains("'identity-link:approve'")
            .contains("'identity-link:reject'")
            .contains("INSERT INTO subject_role_permission_scopes")
            .contains("JOIN role_permission_policies policy ON policy.role_id = role.id")
            .contains("role.code IN ('SUPER_ADMIN', 'SECURITY_ADMIN')")
            .contains("ON CONFLICT DO NOTHING")
            .contains("UPDATE authorization_subjects subject")
            .contains("authorization_version = authorization_version + 1");
    }
}
