package com.vistay.user.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import graphql.GraphqlErrorException;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

class ProfileAdministrationServiceTest {
    private JdbcClient jdbc;
    private IdentityProtection protection;
    private ProfileAdministrationService service;

    @BeforeEach
    void setUp() {
        jdbc = mock(JdbcClient.class);
        protection = mock(IdentityProtection.class);
        service = new ProfileAdministrationService(
            jdbc,
            mock(TransactionTemplate.class),
            JsonMapper.builder().build(),
            protection
        );
    }

    @Test
    void requiresAtLeastOneCustomerContactBeforeProtectingIdentity() {
        var draft = customer(null, null, "VN", "CCCD", "001234567890");

        assertThatThrownBy(() -> service.createCustomer(UUID.randomUUID(), draft))
            .isInstanceOf(GraphqlErrorException.class)
            .hasMessageContaining("email or phone number is required");

        verifyNoInteractions(protection, jdbc);
    }

    @Test
    void rejectsCccdForForeignNationalityBeforeCallingVault() {
        var draft = customer("guest@example.test", null, "US", "CCCD", "001234567890");

        assertThatThrownBy(() -> service.createCustomer(UUID.randomUUID(), draft))
            .isInstanceOf(GraphqlErrorException.class)
            .hasMessageContaining("Foreign customers must use a passport");

        verifyNoInteractions(protection, jdbc);
    }

    @Test
    void normalizesForeignPassportAndUsesItsIssuingCountryForVaultLookup() {
        when(protection.protectIdentityDocument("US", "PASSPORT", "A1234567"))
            .thenThrow(new RuntimeException("stop after contract verification"));
        var draft = customer(null, "+84901234567", "us", "passport", "a1234567");

        assertThatThrownBy(() -> service.createCustomer(UUID.randomUUID(), draft))
            .isInstanceOf(GraphqlErrorException.class)
            .hasMessageContaining("Identity document protection is unavailable");

        verify(protection).protectIdentityDocument("US", "PASSPORT", "A1234567");
        verifyNoInteractions(jdbc);
    }

    @Test
    void availabilityCheckHashesTheNormalizedDocumentInVaultBeforeDatabaseLookup() {
        when(protection.hmacIdentityDocument("VN", "CCCD", "001234567890"))
            .thenThrow(new RuntimeException("stop after contract verification"));

        assertThatThrownBy(() -> service.customerIdentityDocumentAvailability(
            "vn", "cccd", "001234567890"
        ))
            .isInstanceOf(GraphqlErrorException.class)
            .hasMessageContaining("Identity document protection is unavailable");

        verify(protection).hmacIdentityDocument("VN", "CCCD", "001234567890");
        verifyNoInteractions(jdbc);
    }

    @Test
    void classifiesDatabaseEmailRaceWithAStableFailureCode() {
        var conflict = new DataIntegrityViolationException("duplicate key violates ux_customer_email");

        var error = ProfileAdministrationService.constraintConflict(conflict);

        assertThat(error.getExtensions()).containsEntry("code", "PROFILE_EMAIL_ALREADY_EXISTS");
    }

    @Test
    void classifiesDatabasePhoneRaceWithAStableFailureCode() {
        var conflict = new DataIntegrityViolationException("duplicate key violates ux_host_phone");

        var error = ProfileAdministrationService.constraintConflict(conflict);

        assertThat(error.getExtensions()).containsEntry("code", "PROFILE_PHONE_ALREADY_EXISTS");
    }

    @Test
    void classifiesProtectedDocumentRaceWithAStableFailureCode() {
        var conflict = new DataIntegrityViolationException(
            "duplicate profile_identity_documents key (lookup_hmac)"
        );

        var error = ProfileAdministrationService.constraintConflict(conflict);

        assertThat(error.getExtensions())
            .containsEntry("code", "PROFILE_IDENTITY_DOCUMENT_ALREADY_EXISTS");
    }

    private static ProfileAdministrationService.CustomerDraft customer(
        String email,
        String phone,
        String nationality,
        String documentType,
        String documentNumber
    ) {
        return new ProfileAdministrationService.CustomerDraft(
            "Nguyen An", email, phone, "1990-01-01", nationality,
            documentType, documentNumber, "Ha Noi", "Create guest profile", "request-1"
        );
    }
}
