package com.vistay.user.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.sql.SQLException;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class InventoryBlockScopeReconciliationMigrationIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_user_inventory_block_reconciliation_test")
        .withUsername("vistay")
        .withPassword("vistay");

    @Test
    void failsFastBehindLegacyWriterThenReconcilesItsStaleBranchEvidence() throws Exception {
        var separator = POSTGRES.getJdbcUrl().contains("?") ? "&" : "?";
        var dataSource = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl() + separator + "currentSchema=app,extensions,public",
            POSTGRES.getUsername(), POSTGRES.getPassword());
        flyway(dataSource).target("12").load().migrate();
        var jdbc = JdbcClient.create(dataSource);

        var subjectId = UUID.randomUUID();
        var accountId = UUID.randomUUID();
        var assignmentId = UUID.randomUUID();
        var originalBranch = UUID.randomUUID();
        var movedBranch = UUID.randomUUID();
        jdbc.sql("""
                INSERT INTO authorization_subjects(
                    id, account_type, auth_account_id, authorization_version)
                VALUES (:subjectId, 'ADMIN', :accountId, 7);

                INSERT INTO admin_users(
                    id, auth_account_id, authorization_subject_id, full_name,
                    user_type, branch_reference_id)
                VALUES (
                    :profileId, :accountId, :subjectId, 'Migration Race Manager',
                    'MANAGER', :branchId
                );

                INSERT INTO subject_role_assignments(id, subject_id, role_id, valid_from)
                SELECT :assignmentId, :subjectId, id, now() - interval '1 hour'
                FROM roles WHERE code = 'MANAGER';
                """)
            .param("subjectId", subjectId)
            .param("accountId", accountId)
            .param("profileId", UUID.randomUUID())
            .param("assignmentId", assignmentId)
            .param("branchId", originalBranch)
            .update();
        assertThat(partitions(jdbc, assignmentId)).containsExactly(originalBranch);

        try (var legacyWriter = dataSource.getConnection()) {
            legacyWriter.setAutoCommit(false);
            try (var statement = legacyWriter.createStatement()) {
                // This models a transaction that wrote before V12's triggers existed.
                statement.execute("SET LOCAL session_replication_role = replica");
            }
            try (var statement = legacyWriter.prepareStatement("""
                    UPDATE admin_users
                    SET branch_reference_id = ?
                    WHERE authorization_subject_id = ?
                    """)) {
                statement.setObject(1, movedBranch);
                statement.setObject(2, subjectId);
                statement.executeUpdate();
            }

            var failure = catchThrowable(() -> flyway(dataSource).load().migrate());
            assertThat(failure).isNotNull();
            assertThat(findSqlState(failure)).isEqualTo("55P03");
            assertThat(flyway(dataSource).load().info().current().getVersion().getVersion())
                .isEqualTo("12");
            legacyWriter.commit();
        }

        assertThat(jdbc.sql("""
                SELECT branch_reference_id FROM admin_users
                WHERE authorization_subject_id = :subjectId
                """).param("subjectId", subjectId).query(UUID.class).single())
            .isEqualTo(movedBranch);
        assertThat(partitions(jdbc, assignmentId)).containsExactly(originalBranch);

        flyway(dataSource).load().migrate();

        assertThat(partitions(jdbc, assignmentId)).containsExactly(movedBranch);
        assertThat(jdbc.sql("""
                SELECT authorization_version FROM authorization_subjects WHERE id = :subjectId
                """).param("subjectId", subjectId).query(Long.class).single())
            .isEqualTo(8);
    }

    private static java.util.List<UUID> partitions(JdbcClient jdbc, UUID assignmentId) {
        return jdbc.sql("""
                SELECT srpp.partition_id
                FROM subject_role_permission_partitions srpp
                JOIN permissions p ON p.id = srpp.permission_id
                WHERE srpp.assignment_id = :assignmentId
                  AND p.code = 'inventory:block'
                ORDER BY srpp.partition_id
                """)
            .param("assignmentId", assignmentId)
            .query(UUID.class)
            .list();
    }

    private static String findSqlState(Throwable failure) {
        for (var current = failure; current != null; current = current.getCause()) {
            if (current instanceof SQLException sql && sql.getSQLState() != null) {
                return sql.getSQLState();
            }
        }
        return null;
    }

    private static org.flywaydb.core.api.configuration.FluentConfiguration flyway(
        DriverManagerDataSource source
    ) {
        return Flyway.configure()
            .dataSource(source)
            .defaultSchema("app")
            .schemas("app")
            .locations("classpath:db/migration");
    }
}
