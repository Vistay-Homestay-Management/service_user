package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ProfileIdentityLinkMigrationContractTest {
    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V16__profile_identity_linking.sql");

    @Test
    void keepsCccdProtectedUniquePerProfileTypeAndVersionsDynamicPolicy() throws Exception {
        var sql = Files.readString(MIGRATION);
        assertThat(sql)
            .contains("profile_identity_documents")
            .contains("lookup_hmac text NOT NULL")
            .contains("encrypted_value text NOT NULL")
            .contains("lookup_key_version integer NOT NULL")
            .contains("encryption_key_version integer NOT NULL")
            .contains("UNIQUE (profile_type, document_country, document_type, lookup_hmac)")
            .doesNotContain("UNIQUE (document_country, document_type, lookup_hmac)")
            .contains("profile_account_links")
            .contains("profile_link_challenges")
            .contains("profile_link_policies")
            .contains("requires_approval")
            .contains("ALTER TABLE admin_users ALTER COLUMN auth_account_id DROP NOT NULL");
    }
}
