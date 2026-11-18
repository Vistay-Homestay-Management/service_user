package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class CustomerIdentityDocumentMigrationContractTest {
    private static final Path MIGRATION = Path.of(
        "src/main/resources/db/migration/V20__customer_nationality_and_identity_documents.sql");

    @Test
    void supportsVietnameseCccdAndCountryScopedPassportsWithoutWeakeningProtection() throws Exception {
        var sql = Files.readString(MIGRATION);
        assertThat(sql)
            .contains("nationality_code SET DEFAULT 'VNM'")
            .contains("document_country = 'VN' AND document_type = 'CCCD'")
            .contains("document_type = 'PASSPORT'")
            .contains("document_country ~ '^[A-Z]{2}$'")
            .doesNotContain("encrypted_value varchar")
            .doesNotContain("document_number");
    }
}
