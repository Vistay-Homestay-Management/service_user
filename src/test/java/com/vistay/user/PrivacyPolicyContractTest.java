package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class PrivacyPolicyContractTest {
    @Test
    void keepsTheApprovedPrivacyAndRetentionControlsVersioned() throws Exception {
        var policy = Files.readString(Path.of("docs/privacy-data-governance-policy.md"));

        assertThat(policy)
            .contains("Collection disabled for MVP")
            .contains("delete 30 days after checkout")
            .contains("hard maximum 90 days")
            .contains("Backups")
            .contains("expire within 35 days")
            .contains("Consent-dependent processing is disabled")
            .contains("PII access requires both action permission and data scope")
            .contains("Logs/traces use IDs, never raw PII or tokens");
    }

    @Test
    void baselineDoesNotPrematurelyCollectGuestDocumentsOrConsent() throws Exception {
        var baseline = Files.readString(Path.of("src/main/resources/db/migration/V2__baseline.sql"))
            .toLowerCase();

        assertThat(baseline)
            .doesNotContain("guest_document")
            .doesNotContain("passport")
            .doesNotContain("consent_record");
    }
}
