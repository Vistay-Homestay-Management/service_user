package com.vistay.user.application;

import com.vistay.user.application.AuthorizationSnapshotService.Grant;
import com.vistay.user.application.AuthorizationSnapshotService.Scope;
import com.vistay.user.application.AuthorizationSnapshotService.Snapshot;
import graphql.GraphqlErrorException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

@Testcontainers
class ProfileServiceIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_user_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static JdbcClient jdbc;
    private static TransactionTemplate transactions;

    private final AuthorizationSnapshotService snapshots = mock(AuthorizationSnapshotService.class);
    private ProfileService service;
    private UUID accountId;
    private UUID profileId;

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
            TRUNCATE TABLE profile_update_requests, audit_events,
                           admin_users, authorization_subjects CASCADE
            """).update();
        reset(snapshots);
        accountId = UUID.randomUUID();
        profileId = UUID.randomUUID();
        var subjectId = UUID.randomUUID();
        jdbc.sql("""
            INSERT INTO authorization_subjects(id, account_type, auth_account_id)
            VALUES (:id, 'ADMIN', :accountId)
            """)
            .param("id", subjectId)
            .param("accountId", accountId)
            .update();
        jdbc.sql("""
            INSERT INTO admin_users(
                id, auth_account_id, authorization_subject_id,
                full_name, email, user_type
            ) VALUES (
                :id, :accountId, :subjectId,
                'Original Operator', 'operator@vistay.test', 'ADMIN'
            )
            """)
            .param("id", profileId)
            .param("accountId", accountId)
            .param("subjectId", subjectId)
            .update();
        service = new ProfileService(
            jdbc, snapshots, transactions, JsonMapper.builder().build()
        );
    }

    @Test
    void updatesSelfProfileWithOptimisticVersionAuditAndIdempotentReplay() {
        allow("profile:update", Scope.SELF);
        var avatarId = UUID.randomUUID();
        var key = UUID.randomUUID().toString();
        var input = new ProfileService.UpdateProfileInput(
            "  ViStay   Operator  ", "+84 901-234-567", avatarId, 0,
            "Cập nhật thông tin liên hệ cá nhân", key
        );

        var first = service.update(accountId, input);
        var replay = service.update(accountId, input);

        assertThat(first.displayName()).isEqualTo("ViStay Operator");
        assertThat(first.contactPhone()).isEqualTo("+84901234567");
        assertThat(first.avatarMediaId()).isEqualTo(avatarId);
        assertThat(first.version()).isEqualTo(1);
        assertThat(first.replayed()).isFalse();
        assertThat(replay.version()).isEqualTo(1);
        assertThat(replay.replayed()).isTrue();
        assertThat(count("profile_update_requests")).isEqualTo(1);
        assertThat(count("audit_events")).isEqualTo(1);
        var audit = jdbc.sql("""
            SELECT action, reason, correlation_id
            FROM audit_events WHERE aggregate_id = :profileId
            """).param("profileId", profileId).query(AuditRow.class).single();
        assertThat(audit.action()).isEqualTo("PROFILE_UPDATED");
        assertThat(audit.reason()).isEqualTo("Cập nhật thông tin liên hệ cá nhân");
        assertThat(audit.correlationId()).isEqualTo(key);
    }

    @Test
    void rejectsStaleExpectedVersionWithoutAuditOrPartialUpdate() {
        allow("profile:update", Scope.SELF);

        assertThatThrownBy(() -> service.update(accountId, new ProfileService.UpdateProfileInput(
            "Changed Operator", null, null, 5,
            "Kiểm tra optimistic concurrency", UUID.randomUUID().toString()
        ))).isInstanceOfSatisfying(GraphqlErrorException.class,
            error -> assertThat(error.getExtensions().get("code")).isEqualTo("VERSION_CONFLICT"));

        assertThat(count("profile_update_requests")).isZero();
        assertThat(count("audit_events")).isZero();
        assertThat(jdbc.sql("SELECT version FROM admin_users WHERE id = :id")
            .param("id", profileId).query(Long.class).single()).isZero();
    }

    @Test
    void rejectsUpdateWithoutSelfScope() {
        allow("profile:read", Scope.SELF);

        assertThatThrownBy(() -> service.update(accountId, new ProfileService.UpdateProfileInput(
            "Changed Operator", null, null, 0,
            "Không có quyền cập nhật hồ sơ", UUID.randomUUID().toString()
        ))).isInstanceOfSatisfying(GraphqlErrorException.class,
            error -> assertThat(error.getExtensions().get("code")).isEqualTo("FORBIDDEN"));
    }

    @Test
    void rejectsIdempotencyKeyReusedWithDifferentPayload() {
        allow("profile:update", Scope.SELF);
        var key = UUID.randomUUID().toString();
        service.update(accountId, new ProfileService.UpdateProfileInput(
            "First Name", null, null, 0, "Lần cập nhật đầu tiên", key
        ));

        assertThatThrownBy(() -> service.update(accountId, new ProfileService.UpdateProfileInput(
            "Second Name", null, null, 1, "Lần cập nhật thứ hai", key
        ))).isInstanceOfSatisfying(GraphqlErrorException.class,
            error -> assertThat(error.getExtensions().get("code")).isEqualTo("IDEMPOTENCY_KEY_REUSED"));
        assertThat(count("audit_events")).isEqualTo(1);
    }

    @Test
    void replayReturnsTheOriginalResultAfterANewerUpdate() {
        allow("profile:update", Scope.SELF);
        var firstKey = UUID.randomUUID().toString();
        var firstInput = new ProfileService.UpdateProfileInput(
            "First Name", "+84901234567", null, 0, "Cập nhật hồ sơ lần đầu", firstKey
        );
        service.update(accountId, firstInput);
        service.update(accountId, new ProfileService.UpdateProfileInput(
            "Second Name", "+84907654321", null, 1,
            "Cập nhật hồ sơ lần thứ hai", UUID.randomUUID().toString()
        ));

        var replay = service.update(accountId, firstInput);

        assertThat(replay.displayName()).isEqualTo("First Name");
        assertThat(replay.contactPhone()).isEqualTo("+84901234567");
        assertThat(replay.version()).isEqualTo(1);
        assertThat(replay.replayed()).isTrue();
        assertThat(count("audit_events")).isEqualTo(2);
    }

    @Test
    void serializesConcurrentRetriesIntoOneUpdateAndOneReplay() throws Exception {
        allow("profile:update", Scope.SELF);
        var input = new ProfileService.UpdateProfileInput(
            "Concurrent Operator", null, null, 0,
            "Kiểm tra cập nhật đồng thời", UUID.randomUUID().toString()
        );
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> {
                start.await();
                return service.update(accountId, input);
            });
            var second = executor.submit(() -> {
                start.await();
                return service.update(accountId, input);
            });
            start.countDown();

            assertThat(List.of(first.get().replayed(), second.get().replayed()))
                .containsExactlyInAnyOrder(false, true);
        }
        assertThat(count("profile_update_requests")).isEqualTo(1);
        assertThat(count("audit_events")).isEqualTo(1);
    }

    private void allow(String permission, Scope scope) {
        when(snapshots.get("ADMIN", accountId)).thenReturn(new Snapshot(
            "ADMIN", accountId, UUID.randomUUID(), profileId, true, 1,
            List.of("SUPER_ADMIN"), List.of(new Grant(permission, List.of(scope)))
        ));
    }

    private long count(String table) {
        return jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
    }

    private record AuditRow(String action, String reason, String correlationId) {}
}
