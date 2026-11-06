package com.vistay.user.application;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers
class HostProvisioningServiceIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_user_host_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static final ObjectMapper JSON = JsonMapper.builder().build();
    private static JdbcClient jdbc;
    private static TransactionTemplate transactions;
    private HostProvisioningService service;

    @BeforeAll
    static void migrate() {
        var separator = POSTGRES.getJdbcUrl().contains("?") ? "&" : "?";
        var dataSource = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl() + separator + "currentSchema=app,extensions,public",
            POSTGRES.getUsername(),
            POSTGRES.getPassword()
        );
        Flyway.configure()
            .dataSource(dataSource)
            .defaultSchema("app")
            .schemas("app")
            .locations("classpath:db/migration")
            .load()
            .migrate();
        jdbc = JdbcClient.create(dataSource);
        transactions = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
    }

    @BeforeEach
    void setUp() {
        jdbc.sql("""
            TRUNCATE TABLE outbox_events, processed_events,
                           authorization_audit_events,
                           subject_role_permission_scopes,
                           subject_role_assignments,
                           hosts, customers, admin_users,
                           authorization_subjects CASCADE
            """).update();
        restoreHostPolicy();
        service = new HostProvisioningService(jdbc, JSON, transactions);
    }

    @Test
    void provisionsHostWithLeastPrivilegeAndProjectsActivationAndDeactivation() throws Exception {
        var accountId = UUID.randomUUID();
        var profileId = UUID.randomUUID();
        var provisioned = event(
            HostProvisioningService.ACCOUNT_PROVISIONED,
            accountId,
            1,
            """
            {
              "accountId":"%s",
              "accountType":"HOST",
              "realm":"HOST",
              "profileId":"%s",
              "email":"host-%s@vistay.test",
              "displayName":"Synthetic Host",
              "preferredLocale":"vi-VN",
              "verificationStatus":"PENDING"
            }
            """.formatted(accountId, profileId, accountId.toString().substring(0, 8))
        );

        service.consume(provisioned);

        assertThat(count("hosts")).isEqualTo(1);
        assertThat(count("authorization_subjects")).isEqualTo(1);
        assertThat(count("subject_role_assignments")).isEqualTo(1);
        assertThat(count("authorization_audit_events")).isEqualTo(1);
        assertThat(count("outbox_events")).isEqualTo(1);
        assertThat(count("processed_events")).isEqualTo(1);
        assertThat(jdbc.sql("SELECT active FROM authorization_subjects WHERE auth_account_id = :id")
            .param("id", accountId).query(Boolean.class).single()).isFalse();
        assertThat(jdbc.sql("SELECT profile_status FROM hosts WHERE auth_account_id = :id")
            .param("id", accountId).query(String.class).single()).isEqualTo("INACTIVE");
        assertThat(jdbc.sql("""
            SELECT count(*) FROM subject_role_permission_scopes srps
            JOIN subject_role_assignments sra ON sra.id = srps.assignment_id
            JOIN roles r ON r.id = sra.role_id
            WHERE r.code = 'HOST_PARTNER' AND srps.scope_type IN ('SELF', 'OWN')
            """).query(Long.class).single()).isGreaterThan(0);
        assertThat(jdbc.sql("""
            SELECT count(*) FROM subject_role_permission_scopes srps
            JOIN subject_role_assignments sra ON sra.id = srps.assignment_id
            JOIN roles r ON r.id = sra.role_id
            WHERE r.code = 'HOST_PARTNER' AND srps.scope_type NOT IN ('SELF', 'OWN')
            """).query(Long.class).single()).isZero();

        var activated = event(
            HostProvisioningService.HOST_IDENTITY_ACTIVATED,
            UUID.randomUUID(),
            2,
            """
            {
              "accountId":"%s",
              "realm":"HOST",
              "subjectType":"HOST",
              "state":"ACTIVE",
              "authorizationVersion":1,
              "activationSource":"KEYCLOAK",
              "aggregateVersion":2
            }
            """.formatted(accountId)
        );
        service.consume(activated);
        service.consume(activated);

        assertThat(jdbc.sql("SELECT active, authorization_version FROM authorization_subjects WHERE auth_account_id = :id")
            .param("id", accountId).query(SubjectState.class).single())
            .isEqualTo(new SubjectState(true, 1));
        assertThat(jdbc.sql("SELECT profile_status FROM hosts WHERE auth_account_id = :id")
            .param("id", accountId).query(String.class).single()).isEqualTo("ACTIVE");
        assertThat(count("authorization_audit_events")).isEqualTo(2);
        assertThat(count("outbox_events")).isEqualTo(2);
        assertThat(count("subject_role_assignments")).isEqualTo(1);

        service.consume(event(
            HostProvisioningService.HOST_LIFECYCLE_CHANGED,
            accountId,
            3,
            """
            {
              "accountId":"%s",
              "realm":"HOST",
              "subjectType":"HOST",
              "previousState":"ACTIVE",
              "state":"SUSPENDED",
              "authorizationVersion":2,
              "reasonCode":"ADMIN_SUSPENSION",
              "actorType":"ADMIN",
              "aggregateVersion":3
            }
            """.formatted(accountId)
        ));
        service.consume(event(
            HostProvisioningService.HOST_LIFECYCLE_CHANGED,
            accountId,
            4,
            """
            {
              "accountId":"%s",
              "realm":"HOST",
              "subjectType":"HOST",
              "previousState":"SUSPENDED",
              "state":"DEACTIVATED",
              "authorizationVersion":3,
              "reasonCode":"ADMIN_DEACTIVATION",
              "actorType":"ADMIN",
              "aggregateVersion":4
            }
            """.formatted(accountId)
        ));

        assertThat(jdbc.sql("SELECT active, authorization_version FROM authorization_subjects WHERE auth_account_id = :id")
            .param("id", accountId).query(SubjectState.class).single())
            .isEqualTo(new SubjectState(false, 3));
        assertThat(jdbc.sql("SELECT profile_status FROM hosts WHERE auth_account_id = :id")
            .param("id", accountId).query(String.class).single()).isEqualTo("INACTIVE");
        assertThat(count("subject_role_assignments")).isEqualTo(1);
        assertThat(count("hosts")).isEqualTo(1);
        assertThat(count("outbox_events")).isEqualTo(4);
        assertThat(count("processed_events")).isEqualTo(4);
    }

    @Test
    void rejectsCrossTypeCollisionWithoutAnyPartialProjection() throws Exception {
        var accountId = UUID.randomUUID();
        var subjectId = UUID.randomUUID();
        jdbc.sql("""
            INSERT INTO authorization_subjects(id, account_type, auth_account_id, active)
            VALUES (:subjectId, 'ADMIN', :accountId, true)
            """)
            .param("subjectId", subjectId).param("accountId", accountId).update();
        jdbc.sql("""
            INSERT INTO admin_users(id, auth_account_id, authorization_subject_id,
                                    full_name, email, user_type, profile_status)
            VALUES (:id, :accountId, :subjectId, 'Existing Admin', 'admin@vistay.test', 'ADMIN', 'ACTIVE')
            """)
            .param("id", UUID.randomUUID()).param("accountId", accountId).param("subjectId", subjectId).update();

        assertThatThrownBy(() -> service.consume(provisionEvent(accountId)))
            .isInstanceOf(HostProvisioningService.HostProvisioningException.class)
            .hasMessageContaining("HOST_SUBJECT_COLLISION");
        assertThat(count("hosts")).isZero();
        assertThat(count("processed_events")).isZero();
        assertThat(count("authorization_audit_events")).isZero();
        assertThat(count("outbox_events")).isZero();
    }

    @Test
    void rejectsOwnershipClaimAndConflictingBusinessReplayAtomically() throws Exception {
        var accountId = UUID.randomUUID();
        var ownershipClaim = event(
            HostProvisioningService.ACCOUNT_PROVISIONED,
            accountId,
            1,
            """
            {
              "accountId":"%s",
              "accountType":"HOST",
              "realm":"HOST",
              "email":"host@vistay.test",
              "displayName":"Synthetic Host",
              "propertyId":"%s"
            }
            """.formatted(accountId, UUID.randomUUID())
        );
        assertThatThrownBy(() -> service.consume(ownershipClaim))
            .isInstanceOf(HostProvisioningService.HostProvisioningException.class)
            .hasMessageContaining("HOST_OWNERSHIP_CLAIM_FORBIDDEN");
        assertThat(count("hosts")).isZero();
        assertThat(count("processed_events")).isZero();

        service.consume(provisionEvent(accountId));
        var conflict = event(
            HostProvisioningService.ACCOUNT_PROVISIONED,
            UUID.randomUUID(),
            1,
            """
            {
              "accountId":"%s",
              "accountType":"HOST",
              "realm":"HOST",
              "email":"host@vistay.test",
              "displayName":"Changed Host"
            }
            """.formatted(accountId)
        );
        assertThatThrownBy(() -> service.consume(conflict))
            .isInstanceOf(HostProvisioningService.HostProvisioningException.class)
            .hasMessageContaining("HOST_EVENT_BUSINESS_CONFLICT");
        assertThat(count("hosts")).isEqualTo(1);
        assertThat(count("processed_events")).isEqualTo(1);
        assertThat(count("outbox_events")).isEqualTo(1);
    }

    @Test
    void rejectsAHostPartnerPolicyMismatchBeforeCommittingAnyProfile() throws Exception {
        var policy = jdbc.sql("""
            SELECT role_id, permission_id, scope_type
            FROM role_permission_policies rpp
            JOIN roles r ON r.id = rpp.role_id
            WHERE r.code = 'HOST_PARTNER' AND rpp.scope_type = 'SELF'
            LIMIT 1
            """).query(PolicyKey.class).single();
        jdbc.sql("""
            UPDATE role_permission_policies
            SET default_scope = false
            WHERE role_id = :roleId AND permission_id = :permissionId AND scope_type = :scopeType
            """)
            .param("roleId", policy.roleId())
            .param("permissionId", policy.permissionId())
            .param("scopeType", policy.scopeType())
            .update();

        try {
            assertThatThrownBy(() -> service.consume(provisionEvent(UUID.randomUUID())))
                .isInstanceOf(HostProvisioningService.HostProvisioningException.class)
                .hasMessageContaining("HOST_AUTHORIZATION_POLICY_INVALID");
            assertThat(count("hosts")).isZero();
            assertThat(count("authorization_subjects")).isZero();
            assertThat(count("subject_role_assignments")).isZero();
            assertThat(count("processed_events")).isZero();
            assertThat(count("authorization_audit_events")).isZero();
            assertThat(count("outbox_events")).isZero();
        } finally {
            jdbc.sql("""
                UPDATE role_permission_policies
                SET default_scope = true
                WHERE role_id = :roleId AND permission_id = :permissionId AND scope_type = :scopeType
                """)
                .param("roleId", policy.roleId())
                .param("permissionId", policy.permissionId())
                .param("scopeType", policy.scopeType())
                .update();
        }
    }

    private HostProvisioningService.EventEnvelope event(
        String type, UUID aggregateId, long aggregateVersion, String data
    )
        throws Exception {
        return new HostProvisioningService.EventEnvelope(
            UUID.randomUUID(), type, 1, aggregateId, aggregateVersion,
            UUID.randomUUID().toString(), null, OffsetDateTime.now(), JSON.readTree(data)
        );
    }

    private HostProvisioningService.EventEnvelope provisionEvent(UUID accountId) throws Exception {
        return event(
            HostProvisioningService.ACCOUNT_PROVISIONED,
            accountId,
            1,
            """
            {
              "accountId":"%s",
              "accountType":"HOST",
              "realm":"HOST",
              "email":"host@vistay.test",
              "displayName":"Synthetic Host"
            }
            """.formatted(accountId)
        );
    }

    private void restoreHostPolicy() {
        jdbc.sql("""
            UPDATE role_permission_policies rpp
            SET default_scope = true
            FROM roles r
            WHERE r.id = rpp.role_id AND r.code = 'HOST_PARTNER'
              AND rpp.scope_type IN ('SELF', 'OWN')
            """).update();
    }

    private long count(String table) {
        return jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
    }

    private record SubjectState(boolean active, long authorizationVersion) {}
    private record PolicyKey(UUID roleId, UUID permissionId, String scopeType) {}
}
