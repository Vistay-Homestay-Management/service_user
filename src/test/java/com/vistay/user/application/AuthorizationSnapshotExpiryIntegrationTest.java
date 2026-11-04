package com.vistay.user.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.json.JsonMapper;

@Testcontainers
class AuthorizationSnapshotExpiryIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_user_authorization_expiry_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static JdbcClient jdbc;

    @BeforeAll
    static void migrate() {
        var separator = POSTGRES.getJdbcUrl().contains("?") ? "&" : "?";
        var dataSource = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl() + separator + "currentSchema=app,extensions,public",
            POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(dataSource).defaultSchema("app").schemas("app")
            .locations("classpath:db/migration").load().migrate();
        jdbc = JdbcClient.create(dataSource);
    }

    @Test
    void excludesExpiredRoleAndItsGrantsFromAuthorizationSnapshot() {
        var accountId = UUID.randomUUID();
        var subjectId = UUID.randomUUID();
        var profileId = UUID.randomUUID();
        var expiredRoleId = UUID.randomUUID();
        var activeRoleId = UUID.randomUUID();
        var expiredPermissionId = UUID.randomUUID();
        var activePermissionId = UUID.randomUUID();
        var expiredAssignmentId = UUID.randomUUID();
        var activeAssignmentId = UUID.randomUUID();

        jdbc.sql("""
            INSERT INTO authorization_subjects(id, account_type, auth_account_id)
            VALUES (:subjectId, 'ADMIN', :accountId);
            INSERT INTO admin_users(
                id, auth_account_id, authorization_subject_id, full_name, email, user_type)
            VALUES (:profileId, :accountId, :subjectId,
                    'Expiry Test Operator', 'expiry-test@vistay.test', 'ADMIN');
            INSERT INTO roles(id, code, display_name, audience)
            VALUES (:expiredRoleId, 'TEST_EXPIRED_ROLE', 'Expired Role', 'ADMIN'),
                   (:activeRoleId, 'TEST_ACTIVE_ROLE', 'Active Role', 'ADMIN');
            INSERT INTO permissions(id, resource, action)
            VALUES (:expiredPermissionId, 'test-expired', 'read'),
                   (:activePermissionId, 'test-active', 'read');
            INSERT INTO role_permissions(role_id, permission_id)
            VALUES (:expiredRoleId, :expiredPermissionId),
                   (:activeRoleId, :activePermissionId);
            INSERT INTO subject_role_assignments(
                id, subject_id, role_id, valid_from, valid_until)
            VALUES (:expiredAssignmentId, :subjectId, :expiredRoleId,
                    now() - interval '2 days', now() - interval '1 day'),
                   (:activeAssignmentId, :subjectId, :activeRoleId,
                    now() - interval '1 day', now() + interval '1 day');
            INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
            VALUES (:expiredAssignmentId, :expiredPermissionId, 'ALL'),
                   (:activeAssignmentId, :activePermissionId, 'ALL');
            """)
            .param("subjectId", subjectId).param("accountId", accountId)
            .param("profileId", profileId)
            .param("expiredRoleId", expiredRoleId).param("activeRoleId", activeRoleId)
            .param("expiredPermissionId", expiredPermissionId)
            .param("activePermissionId", activePermissionId)
            .param("expiredAssignmentId", expiredAssignmentId)
            .param("activeAssignmentId", activeAssignmentId)
            .update();

        var redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        var service = new AuthorizationSnapshotService(
            jdbc, redis, JsonMapper.builder().build(), Duration.ofMinutes(1));

        var snapshot = service.get("ADMIN", accountId);

        assertThat(snapshot.roles()).containsExactly("TEST_ACTIVE_ROLE");
        assertThat(snapshot.permissions()).containsExactly("test-active:read");
        assertThat(snapshot.permissions()).doesNotContain("test-expired:read");
    }
}
