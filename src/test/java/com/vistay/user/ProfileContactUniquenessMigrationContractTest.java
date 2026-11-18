package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ProfileContactUniquenessMigrationContractTest {
    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V21__profile_contact_uniqueness.sql");

    @Test
    void keepsContactUniquenessInsideEachProfileType() throws Exception {
        var sql = Files.readString(MIGRATION);

        assertThat(sql)
            .contains("CREATE TABLE profile_contact_claims")
            .contains("PRIMARY KEY (profile_type, contact_kind, normalized_value)")
            .contains("DISTINCT ON (lower(email::text))")
            .contains("DISTINCT ON (normalized_phone)")
            .contains("ux_profile_contact_email")
            .contains("ux_profile_contact_phone")
            .contains("CREATE TRIGGER trg_customer_contact_claims")
            .contains("CREATE TRIGGER trg_admin_contact_claims")
            .contains("CREATE TRIGGER trg_host_contact_claims");
    }
}
