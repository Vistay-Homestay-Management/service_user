package com.vistay.user.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class InventoryBlockScopeMigrationIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_user_inventory_block_scope_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static final UUID SUPER_SUBJECT = uuid("11000000-0000-4000-8000-000000000001");
    private static final UUID MANAGER_SUBJECT = uuid("11000000-0000-4000-8000-000000000002");
    private static final UUID REDUCED_MANAGER_SUBJECT = uuid("11000000-0000-4000-8000-000000000003");
    private static final UUID NULL_BRANCH_SUBJECT = uuid("11000000-0000-4000-8000-000000000004");
    private static final UUID RECEPTIONIST_SUBJECT = uuid("11000000-0000-4000-8000-000000000005");
    private static final UUID STAFF_SUBJECT = uuid("11000000-0000-4000-8000-000000000006");
    private static final UUID CTV_SUBJECT = uuid("11000000-0000-4000-8000-000000000007");
    private static final UUID HOST_SUBJECT = uuid("11000000-0000-4000-8000-000000000008");

    private static final UUID SUPER_ASSIGNMENT = uuid("21000000-0000-4000-8000-000000000001");
    private static final UUID MANAGER_ASSIGNMENT = uuid("21000000-0000-4000-8000-000000000002");
    private static final UUID REDUCED_MANAGER_ASSIGNMENT = uuid("21000000-0000-4000-8000-000000000003");
    private static final UUID NULL_BRANCH_ASSIGNMENT = uuid("21000000-0000-4000-8000-000000000004");
    private static final UUID RECEPTIONIST_ASSIGNMENT = uuid("21000000-0000-4000-8000-000000000005");
    private static final UUID STAFF_ASSIGNMENT = uuid("21000000-0000-4000-8000-000000000006");
    private static final UUID CTV_ASSIGNMENT = uuid("21000000-0000-4000-8000-000000000007");
    private static final UUID HOST_ASSIGNMENT = uuid("21000000-0000-4000-8000-000000000008");

    private static final UUID MANAGER_BRANCH = uuid("31000000-0000-4000-8000-000000000001");
    private static final UUID RECEPTIONIST_BRANCH = uuid("31000000-0000-4000-8000-000000000002");
    private static final UUID STAFF_BRANCH = uuid("31000000-0000-4000-8000-000000000003");
    private static final UUID CTV_BRANCH = uuid("31000000-0000-4000-8000-000000000004");
    private static final UUID STALE_BRANCH = uuid("31000000-0000-4000-8000-000000000005");

    private static JdbcClient jdbc;
    private static DriverManagerDataSource dataSource;

    @BeforeAll
    static void migrateAroundLegacyInventoryBlockScopes() {
        var separator = POSTGRES.getJdbcUrl().contains("?") ? "&" : "?";
        dataSource = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl() + separator + "currentSchema=app,extensions,public",
            POSTGRES.getUsername(), POSTGRES.getPassword());

        flyway(dataSource).target("11").load().migrate();
        jdbc = JdbcClient.create(dataSource);
        seedLegacyAssignments();
        flyway(dataSource).load().migrate();
    }

    @Test
    void restrictsCatalogToSuperAdminAllAndManagerBranch() {
        var rolePermissions = jdbc.sql("""
                SELECT r.code
                FROM role_permissions rp
                JOIN roles r ON r.id = rp.role_id
                JOIN permissions p ON p.id = rp.permission_id
                WHERE p.code = 'inventory:block'
                ORDER BY r.code
                """)
            .query(String.class)
            .list();
        assertThat(rolePermissions).containsExactly("MANAGER", "SUPER_ADMIN");

        var policies = jdbc.sql("""
                SELECT r.code AS role_code, rpp.scope_type, rpp.default_scope
                FROM role_permission_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                JOIN permissions p ON p.id = rpp.permission_id
                WHERE p.code = 'inventory:block'
                ORDER BY r.code, rpp.scope_type
                """)
            .query(ScopePolicyRow.class)
            .list();
        assertThat(policies).containsExactly(
            new ScopePolicyRow("MANAGER", "ASSIGNED", true),
            new ScopePolicyRow("SUPER_ADMIN", "ALL", true));

        var partitionPolicies = jdbc.sql("""
                SELECT r.code AS role_code, rpp.partition_type
                FROM role_permission_partition_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                JOIN permissions p ON p.id = rpp.permission_id
                WHERE p.code = 'inventory:block'
                ORDER BY r.code, rpp.partition_type
                """)
            .query(PartitionPolicyRow.class)
            .list();
        assertThat(partitionPolicies).containsExactly(
            new PartitionPolicyRow("MANAGER", "BRANCH"));
    }

    @Test
    void repairsElevatedEvidenceWithoutRegrantingMissingManagerPermission() {
        assertThat(inventoryBlockScopesFor(SUPER_ASSIGNMENT)).containsExactly("ALL");
        assertThat(inventoryBlockScopesFor(MANAGER_ASSIGNMENT)).containsExactly("ASSIGNED");
        assertThat(inventoryBlockScopesFor(NULL_BRANCH_ASSIGNMENT)).containsExactly("ASSIGNED");
        assertThat(inventoryBlockScopesFor(REDUCED_MANAGER_ASSIGNMENT)).isEmpty();

        for (var assignment : List.of(
            RECEPTIONIST_ASSIGNMENT, STAFF_ASSIGNMENT, CTV_ASSIGNMENT, HOST_ASSIGNMENT)) {
            assertThat(inventoryBlockScopesFor(assignment)).isEmpty();
            assertThat(inventoryBlockPartitionsFor(assignment)).isEmpty();
        }

        assertThat(inventoryBlockPartitionsFor(MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("BRANCH", MANAGER_BRANCH));
        assertThat(inventoryBlockPartitionsFor(NULL_BRANCH_ASSIGNMENT)).isEmpty();
        assertThat(inventoryBlockPartitionsFor(REDUCED_MANAGER_ASSIGNMENT)).isEmpty();
        assertThat(inventoryBlockPartitionsFor(SUPER_ASSIGNMENT)).isEmpty();

        assertThat(authorizationVersion(SUPER_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(MANAGER_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(NULL_BRANCH_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(REDUCED_MANAGER_SUBJECT)).isEqualTo(20);
        assertThat(authorizationVersion(RECEPTIONIST_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(STAFF_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(CTV_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(HOST_SUBJECT)).isEqualTo(21);
    }

    @Test
    void synchronizesManagerLifecycleAndPreservesLaterReduction() {
        var manager = insertNewAdminAssignment("MANAGER", UUID.randomUUID());
        assertThat(inventoryBlockScopesFor(manager.assignmentId())).containsExactly("ASSIGNED");
        assertThat(inventoryBlockPartitionsFor(manager.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", manager.branchId()));

        var receptionist = insertNewAdminAssignment("RECEPTIONIST", UUID.randomUUID());
        assertThat(inventoryBlockScopesFor(receptionist.assignmentId())).isEmpty();
        assertThat(inventoryBlockPartitionsFor(receptionist.assignmentId())).isEmpty();

        var movedBranch = UUID.randomUUID();
        var versionBeforeMove = authorizationVersion(manager.subjectId());
        updateBranch(manager.subjectId(), movedBranch);
        assertThat(inventoryBlockPartitionsFor(manager.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", movedBranch));
        assertThat(authorizationVersion(manager.subjectId())).isEqualTo(versionBeforeMove + 1);

        revokeAssignment(manager.assignmentId());
        assertThat(inventoryBlockScopesFor(manager.assignmentId())).containsExactly("ASSIGNED");
        assertThat(inventoryBlockPartitionsFor(manager.assignmentId())).isEmpty();

        reinstateAssignment(manager.assignmentId());
        assertThat(inventoryBlockPartitionsFor(manager.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", movedBranch));

        deleteInventoryBlockScope(manager.assignmentId());
        assertThat(inventoryBlockScopesFor(manager.assignmentId())).isEmpty();
        assertThat(inventoryBlockPartitionsFor(manager.assignmentId())).isEmpty();
        updateBranch(manager.subjectId(), UUID.randomUUID());
        revokeAssignment(manager.assignmentId());
        reinstateAssignment(manager.assignmentId());
        assertThat(inventoryBlockScopesFor(manager.assignmentId())).isEmpty();
        assertThat(inventoryBlockPartitionsFor(manager.assignmentId())).isEmpty();

        insertInventoryBlockScope(manager.assignmentId(), "ASSIGNED");
        assertThat(inventoryBlockPartitionsFor(manager.assignmentId())).hasSize(1);

        var nullBranchManager = insertNewAdminAssignment("MANAGER", null);
        assertThat(inventoryBlockScopesFor(nullBranchManager.assignmentId()))
            .containsExactly("ASSIGNED");
        assertThat(inventoryBlockPartitionsFor(nullBranchManager.assignmentId())).isEmpty();
    }

    @Test
    void rejectsCatalogScopeAndPartitionEscalation() {
        for (var forbiddenRole : List.of("RECEPTIONIST", "STAFF", "CTV", "HOST_PARTNER")) {
            assertThatThrownBy(() -> insertInventoryBlockRolePermission(forbiddenRole))
                .as("inventory:block role permission for %s", forbiddenRole)
                .isInstanceOf(DataAccessException.class);
        }

        assertThatThrownBy(() -> insertRoleScopePolicy("MANAGER", "ALL"))
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> insertRoleScopePolicy("SUPER_ADMIN", "ASSIGNED"))
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> insertRolePartitionPolicy("MANAGER", "AREA"))
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> insertRolePartitionPolicy("SUPER_ADMIN", "BRANCH"))
            .isInstanceOf(DataAccessException.class);

        var manager = insertNewAdminAssignment("MANAGER", UUID.randomUUID());
        assertThatThrownBy(() -> insertInventoryBlockScope(manager.assignmentId(), "ALL"))
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.sql("""
                UPDATE subject_role_permission_scopes srps
                SET scope_type = 'ALL'
                FROM permissions p
                WHERE srps.assignment_id = :assignmentId
                  AND srps.permission_id = p.id
                  AND p.code = 'inventory:block'
                  AND srps.scope_type = 'ASSIGNED'
                """)
            .param("assignmentId", manager.assignmentId())
            .update())
            .isInstanceOf(DataAccessException.class);

        var receptionist = insertNewAdminAssignment("RECEPTIONIST", UUID.randomUUID());
        assertThatThrownBy(() -> insertInventoryBlockScope(receptionist.assignmentId(), "ASSIGNED"))
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> insertInventoryBlockScope(SUPER_ASSIGNMENT, "ASSIGNED"))
            .isInstanceOf(DataAccessException.class);

        assertThatThrownBy(() -> insertInventoryBlockPartition(
            manager.assignmentId(), "BRANCH", UUID.randomUUID()))
            .as("foreign branch")
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> insertInventoryBlockPartition(
            manager.assignmentId(), "AREA", manager.branchId()))
            .as("wrong partition type")
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> insertInventoryBlockPartition(
            SUPER_ASSIGNMENT, "BRANCH", MANAGER_BRANCH))
            .as("SUPER_ADMIN partition")
            .isInstanceOf(DataAccessException.class);

        deleteInventoryBlockScope(manager.assignmentId());
        assertThatThrownBy(() -> insertInventoryBlockPartition(
            manager.assignmentId(), "BRANCH", manager.branchId()))
            .as("partition without ASSIGNED")
            .isInstanceOf(DataAccessException.class);

        insertInventoryBlockScope(manager.assignmentId(), "ASSIGNED");
        revokeAssignment(manager.assignmentId());
        assertThatThrownBy(() -> insertInventoryBlockPartition(
            manager.assignmentId(), "BRANCH", manager.branchId()))
            .as("partition on revoked assignment")
            .isInstanceOf(DataAccessException.class);
    }

    @Test
    void serializesConcurrentPartitionWriteWithBranchMovement() throws Exception {
        var manager = insertNewAdminAssignment("MANAGER", UUID.randomUUID());
        var movedBranch = UUID.randomUUID();
        deleteInventoryBlockPartitions(manager.assignmentId());

        var partitionInserted = new CountDownLatch(1);
        var releasePartitionTransaction = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var partitionWrite = executor.submit(() -> {
                try (var connection = dataSource.getConnection()) {
                    connection.setAutoCommit(false);
                    insertInventoryBlockPartition(
                        connection, manager.assignmentId(), "BRANCH", manager.branchId());
                    partitionInserted.countDown();
                    if (!releasePartitionTransaction.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to commit partition write");
                    }
                    connection.commit();
                }
                return null;
            });

            assertThat(partitionInserted.await(5, TimeUnit.SECONDS)).isTrue();
            var branchMove = executor.submit(() -> {
                try (var connection = dataSource.getConnection()) {
                    connection.setAutoCommit(false);
                    updateBranch(connection, manager.subjectId(), movedBranch);
                    connection.commit();
                }
                return null;
            });

            try {
                assertThatThrownBy(() -> branchMove.get(500, TimeUnit.MILLISECONDS))
                    .isInstanceOf(TimeoutException.class);
            } finally {
                releasePartitionTransaction.countDown();
            }

            partitionWrite.get(5, TimeUnit.SECONDS);
            branchMove.get(5, TimeUnit.SECONDS);
        } finally {
            releasePartitionTransaction.countDown();
            executor.shutdownNow();
        }

        assertThat(inventoryBlockPartitionsFor(manager.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", movedBranch));
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

    private static void seedLegacyAssignments() {
        insertAdmin(SUPER_SUBJECT, "ADMIN", null, "Legacy Super Admin");
        insertAdmin(MANAGER_SUBJECT, "MANAGER", MANAGER_BRANCH, "Legacy Manager");
        insertAdmin(
            REDUCED_MANAGER_SUBJECT, "MANAGER", UUID.randomUUID(), "Reduced Manager");
        insertAdmin(NULL_BRANCH_SUBJECT, "MANAGER", null, "Null Branch Manager");
        insertAdmin(
            RECEPTIONIST_SUBJECT, "RECEPTIONIST", RECEPTIONIST_BRANCH, "Legacy Receptionist");
        insertAdmin(STAFF_SUBJECT, "STAFF", STAFF_BRANCH, "Legacy Staff");
        insertAdmin(CTV_SUBJECT, "CTV", CTV_BRANCH, "Legacy CTV");
        insertHost(HOST_SUBJECT, "Legacy Host");

        insertAssignment(SUPER_ASSIGNMENT, SUPER_SUBJECT, "SUPER_ADMIN");
        insertAssignment(MANAGER_ASSIGNMENT, MANAGER_SUBJECT, "MANAGER");
        insertAssignment(REDUCED_MANAGER_ASSIGNMENT, REDUCED_MANAGER_SUBJECT, "MANAGER");
        insertAssignment(NULL_BRANCH_ASSIGNMENT, NULL_BRANCH_SUBJECT, "MANAGER");
        insertAssignment(RECEPTIONIST_ASSIGNMENT, RECEPTIONIST_SUBJECT, "RECEPTIONIST");
        insertAssignment(STAFF_ASSIGNMENT, STAFF_SUBJECT, "STAFF");
        insertAssignment(CTV_ASSIGNMENT, CTV_SUBJECT, "CTV");
        insertAssignment(HOST_ASSIGNMENT, HOST_SUBJECT, "HOST_PARTNER");

        for (var role : List.of("RECEPTIONIST", "STAFF", "CTV", "HOST_PARTNER")) {
            insertInventoryBlockRolePermissionUnchecked(role);
        }

        insertInventoryBlockScope(SUPER_ASSIGNMENT, "ASSIGNED");
        insertInventoryBlockScope(MANAGER_ASSIGNMENT, "ALL");
        insertInventoryBlockScope(NULL_BRANCH_ASSIGNMENT, "ALL");
        insertInventoryBlockScope(RECEPTIONIST_ASSIGNMENT, "ALL");
        insertInventoryBlockScope(STAFF_ASSIGNMENT, "ALL");
        insertInventoryBlockScope(CTV_ASSIGNMENT, "ALL");
        insertInventoryBlockScope(HOST_ASSIGNMENT, "ALL");

        insertInventoryBlockPartition(SUPER_ASSIGNMENT, "AREA", STALE_BRANCH);
        insertInventoryBlockPartition(MANAGER_ASSIGNMENT, "AREA", STALE_BRANCH);
        insertInventoryBlockPartition(MANAGER_ASSIGNMENT, "BRANCH", STALE_BRANCH);
        insertInventoryBlockPartition(RECEPTIONIST_ASSIGNMENT, "BRANCH", RECEPTIONIST_BRANCH);
        insertInventoryBlockPartition(STAFF_ASSIGNMENT, "BRANCH", STAFF_BRANCH);
        insertInventoryBlockPartition(CTV_ASSIGNMENT, "BRANCH", CTV_BRANCH);
        insertInventoryBlockPartition(HOST_ASSIGNMENT, "AREA", STALE_BRANCH);

        insertRolePartitionPolicy("SUPER_ADMIN", "AREA");
        insertRolePartitionPolicy("MANAGER", "AREA");
        insertRoleScopePolicy("RECEPTIONIST", "ALL");
        insertRolePartitionPolicy("RECEPTIONIST", "AREA");
    }

    private static OperationalFixture insertNewAdminAssignment(String role, UUID branchId) {
        var subjectId = UUID.randomUUID();
        var assignmentId = UUID.randomUUID();
        insertAdmin(subjectId, role, branchId, "Lifecycle " + role);
        insertAssignment(assignmentId, subjectId, role);
        return new OperationalFixture(subjectId, assignmentId, branchId);
    }

    private static void insertAdmin(UUID subjectId, String userType, UUID branchId, String fullName) {
        var accountId = UUID.randomUUID();
        jdbc.sql("""
                INSERT INTO authorization_subjects(
                    id, account_type, auth_account_id, authorization_version)
                VALUES (:subjectId, 'ADMIN', :accountId, 20);

                INSERT INTO admin_users(
                    id, auth_account_id, authorization_subject_id, full_name,
                    user_type, branch_reference_id)
                VALUES (:profileId, :accountId, :subjectId, :fullName, :userType, :branchId);
                """)
            .param("subjectId", subjectId)
            .param("accountId", accountId)
            .param("profileId", UUID.randomUUID())
            .param("fullName", fullName)
            .param("userType", userType)
            .param("branchId", branchId)
            .update();
    }

    private static void insertHost(UUID subjectId, String fullName) {
        var accountId = UUID.randomUUID();
        jdbc.sql("""
                INSERT INTO authorization_subjects(
                    id, account_type, auth_account_id, authorization_version)
                VALUES (:subjectId, 'HOST', :accountId, 20);

                INSERT INTO hosts(
                    id, auth_account_id, authorization_subject_id, full_name)
                VALUES (:profileId, :accountId, :subjectId, :fullName);
                """)
            .param("subjectId", subjectId)
            .param("accountId", accountId)
            .param("profileId", UUID.randomUUID())
            .param("fullName", fullName)
            .update();
    }

    private static void insertAssignment(UUID assignmentId, UUID subjectId, String role) {
        jdbc.sql("""
                INSERT INTO subject_role_assignments(id, subject_id, role_id, valid_from)
                SELECT :assignmentId, :subjectId, id, now() - interval '1 hour'
                FROM roles
                WHERE code = :role
                """)
            .param("assignmentId", assignmentId)
            .param("subjectId", subjectId)
            .param("role", role)
            .update();
    }

    private static void insertInventoryBlockRolePermissionUnchecked(String role) {
        jdbc.sql("""
                INSERT INTO role_permissions(role_id, permission_id)
                SELECT r.id, p.id
                FROM roles r
                JOIN permissions p ON p.code = 'inventory:block'
                WHERE r.code = :role
                ON CONFLICT DO NOTHING
                """)
            .param("role", role)
            .update();
    }

    private static void insertInventoryBlockRolePermission(String role) {
        insertInventoryBlockRolePermissionUnchecked(role);
    }

    private static void insertInventoryBlockScope(UUID assignmentId, String scopeType) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_scopes(
                    assignment_id, permission_id, scope_type)
                SELECT :assignmentId, id, :scopeType
                FROM permissions
                WHERE code = 'inventory:block'
                """)
            .param("assignmentId", assignmentId)
            .param("scopeType", scopeType)
            .update();
    }

    private static void insertInventoryBlockPartition(
        UUID assignmentId,
        String partitionType,
        UUID partitionId
    ) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_partitions(
                    assignment_id, permission_id, partition_type, partition_id)
                SELECT :assignmentId, id, :partitionType, :partitionId
                FROM permissions
                WHERE code = 'inventory:block'
                """)
            .param("assignmentId", assignmentId)
            .param("partitionType", partitionType)
            .param("partitionId", partitionId)
            .update();
    }

    private static void insertInventoryBlockPartition(
        Connection connection,
        UUID assignmentId,
        String partitionType,
        UUID partitionId
    ) throws SQLException {
        try (var statement = connection.prepareStatement("""
                INSERT INTO subject_role_permission_partitions(
                    assignment_id, permission_id, partition_type, partition_id)
                SELECT ?, id, ?, ?
                FROM permissions
                WHERE code = 'inventory:block'
                """)) {
            statement.setObject(1, assignmentId);
            statement.setString(2, partitionType);
            statement.setObject(3, partitionId);
            statement.executeUpdate();
        }
    }

    private static void insertRoleScopePolicy(String role, String scopeType) {
        jdbc.sql("""
                INSERT INTO role_permission_policies(
                    role_id, permission_id, scope_type, default_scope)
                SELECT r.id, p.id, :scopeType, false
                FROM roles r
                JOIN permissions p ON p.code = 'inventory:block'
                WHERE r.code = :role
                """)
            .param("role", role)
            .param("scopeType", scopeType)
            .update();
    }

    private static void insertRolePartitionPolicy(String role, String partitionType) {
        jdbc.sql("""
                INSERT INTO role_permission_partition_policies(
                    role_id, permission_id, partition_type)
                SELECT r.id, p.id, :partitionType
                FROM roles r
                JOIN permissions p ON p.code = 'inventory:block'
                WHERE r.code = :role
                """)
            .param("role", role)
            .param("partitionType", partitionType)
            .update();
    }

    private static void deleteInventoryBlockScope(UUID assignmentId) {
        jdbc.sql("""
                DELETE FROM subject_role_permission_scopes srps
                USING permissions p
                WHERE srps.assignment_id = :assignmentId
                  AND srps.permission_id = p.id
                  AND p.code = 'inventory:block'
                  AND srps.scope_type = 'ASSIGNED'
                """)
            .param("assignmentId", assignmentId)
            .update();
    }

    private static void deleteInventoryBlockPartitions(UUID assignmentId) {
        jdbc.sql("""
                DELETE FROM subject_role_permission_partitions srpp
                USING permissions p
                WHERE srpp.assignment_id = :assignmentId
                  AND srpp.permission_id = p.id
                  AND p.code = 'inventory:block'
                """)
            .param("assignmentId", assignmentId)
            .update();
    }

    private static void updateBranch(UUID subjectId, UUID branchId) {
        jdbc.sql("""
                UPDATE admin_users
                SET branch_reference_id = :branchId
                WHERE authorization_subject_id = :subjectId
                """)
            .param("subjectId", subjectId)
            .param("branchId", branchId)
            .update();
    }

    private static void updateBranch(Connection connection, UUID subjectId, UUID branchId)
        throws SQLException {
        try (var statement = connection.prepareStatement("""
                UPDATE admin_users
                SET branch_reference_id = ?
                WHERE authorization_subject_id = ?
                """)) {
            statement.setObject(1, branchId);
            statement.setObject(2, subjectId);
            statement.executeUpdate();
        }
    }

    private static void revokeAssignment(UUID assignmentId) {
        jdbc.sql("""
                UPDATE subject_role_assignments
                SET revoked_at = now(), revoke_reason = 'Inventory block lifecycle test'
                WHERE id = :assignmentId
                """)
            .param("assignmentId", assignmentId)
            .update();
    }

    private static void reinstateAssignment(UUID assignmentId) {
        jdbc.sql("""
                UPDATE subject_role_assignments
                SET revoked_at = NULL, revoke_reason = NULL
                WHERE id = :assignmentId
                """)
            .param("assignmentId", assignmentId)
            .update();
    }

    private static List<String> inventoryBlockScopesFor(UUID assignmentId) {
        return jdbc.sql("""
                SELECT srps.scope_type
                FROM subject_role_permission_scopes srps
                JOIN permissions p ON p.id = srps.permission_id
                WHERE srps.assignment_id = :assignmentId
                  AND p.code = 'inventory:block'
                ORDER BY srps.scope_type
                """)
            .param("assignmentId", assignmentId)
            .query(String.class)
            .list();
    }

    private static List<PartitionBindingRow> inventoryBlockPartitionsFor(UUID assignmentId) {
        return jdbc.sql("""
                SELECT srpp.partition_type, srpp.partition_id
                FROM subject_role_permission_partitions srpp
                JOIN permissions p ON p.id = srpp.permission_id
                WHERE srpp.assignment_id = :assignmentId
                  AND p.code = 'inventory:block'
                ORDER BY srpp.partition_type, srpp.partition_id
                """)
            .param("assignmentId", assignmentId)
            .query(PartitionBindingRow.class)
            .list();
    }

    private static long authorizationVersion(UUID subjectId) {
        return jdbc.sql("""
                SELECT authorization_version
                FROM authorization_subjects
                WHERE id = :subjectId
                """)
            .param("subjectId", subjectId)
            .query(Long.class)
            .single();
    }

    private static UUID uuid(String value) {
        return UUID.fromString(value);
    }

    private record ScopePolicyRow(String roleCode, String scopeType, boolean defaultScope) {}

    private record PartitionPolicyRow(String roleCode, String partitionType) {}

    private record PartitionBindingRow(String partitionType, UUID partitionId) {}

    private record OperationalFixture(UUID subjectId, UUID assignmentId, UUID branchId) {}
}
