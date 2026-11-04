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
class InventoryReadScopeMigrationIntegrationTest {

    private static final List<String> BRANCH_ROLES = List.of(
        "MANAGER", "RECEPTIONIST", "STAFF");

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_user_inventory_scope_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static final UUID SUPER_SUBJECT = uuid("10000000-0000-4000-8000-000000000001");
    private static final UUID CTV_SUBJECT = uuid("10000000-0000-4000-8000-000000000002");
    private static final UUID MANAGER_SUBJECT = uuid("10000000-0000-4000-8000-000000000003");
    private static final UUID RECEPTIONIST_SUBJECT = uuid("10000000-0000-4000-8000-000000000004");
    private static final UUID STAFF_SUBJECT = uuid("10000000-0000-4000-8000-000000000005");
    private static final UUID NULL_BRANCH_SUBJECT = uuid("10000000-0000-4000-8000-000000000006");
    private static final UUID REDUCED_STAFF_SUBJECT = uuid("10000000-0000-4000-8000-000000000007");

    private static final UUID SUPER_ASSIGNMENT = uuid("20000000-0000-4000-8000-000000000001");
    private static final UUID CTV_ASSIGNMENT = uuid("20000000-0000-4000-8000-000000000002");
    private static final UUID MANAGER_ASSIGNMENT = uuid("20000000-0000-4000-8000-000000000003");
    private static final UUID RECEPTIONIST_ASSIGNMENT = uuid("20000000-0000-4000-8000-000000000004");
    private static final UUID STAFF_ASSIGNMENT = uuid("20000000-0000-4000-8000-000000000005");
    private static final UUID NULL_BRANCH_ASSIGNMENT = uuid("20000000-0000-4000-8000-000000000006");
    private static final UUID REDUCED_STAFF_ASSIGNMENT = uuid("20000000-0000-4000-8000-000000000007");

    private static final UUID MANAGER_BRANCH = uuid("30000000-0000-4000-8000-000000000001");
    private static final UUID RECEPTIONIST_BRANCH = uuid("30000000-0000-4000-8000-000000000002");
    private static final UUID STAFF_BRANCH = uuid("30000000-0000-4000-8000-000000000003");
    private static final UUID REDUCED_STAFF_BRANCH = uuid("30000000-0000-4000-8000-000000000004");
    private static final UUID STALE_BRANCH = uuid("30000000-0000-4000-8000-000000000005");

    private static JdbcClient jdbc;
    private static DriverManagerDataSource dataSource;

    @BeforeAll
    static void migrateAroundLegacyInventoryScopes() {
        var separator = POSTGRES.getJdbcUrl().contains("?") ? "&" : "?";
        dataSource = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl() + separator + "currentSchema=app,extensions,public",
            POSTGRES.getUsername(), POSTGRES.getPassword());

        flyway(dataSource).target("10").load().migrate();
        jdbc = JdbcClient.create(dataSource);
        seedLegacyAssignments();
        flyway(dataSource).load().migrate();
    }

    @Test
    void keepsGlobalReadersAndRestrictsOperationalRolePoliciesToBranch() {
        var policies = jdbc.sql("""
                SELECT r.code AS role_code, rpp.scope_type, rpp.default_scope
                FROM role_permission_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                JOIN permissions p ON p.id = rpp.permission_id
                WHERE r.code IN ('SUPER_ADMIN', 'CTV', 'MANAGER', 'RECEPTIONIST', 'STAFF')
                  AND p.code = 'inventory:read'
                ORDER BY r.code, rpp.scope_type
                """)
            .query(ScopePolicyRow.class)
            .list();

        assertThat(policies).containsExactly(
            new ScopePolicyRow("CTV", "ALL", true),
            new ScopePolicyRow("MANAGER", "ASSIGNED", true),
            new ScopePolicyRow("RECEPTIONIST", "ASSIGNED", true),
            new ScopePolicyRow("STAFF", "ASSIGNED", true),
            new ScopePolicyRow("SUPER_ADMIN", "ALL", true));

        var partitionPolicies = jdbc.sql("""
                SELECT r.code AS role_code, rpp.partition_type
                FROM role_permission_partition_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                JOIN permissions p ON p.id = rpp.permission_id
                WHERE r.code IN ('SUPER_ADMIN', 'CTV', 'MANAGER', 'RECEPTIONIST', 'STAFF')
                  AND p.code = 'inventory:read'
                ORDER BY r.code, rpp.partition_type
                """)
            .query(PartitionPolicyRow.class)
            .list();

        assertThat(partitionPolicies).containsExactly(
            new PartitionPolicyRow("MANAGER", "BRANCH"),
            new PartitionPolicyRow("RECEPTIONIST", "BRANCH"),
            new PartitionPolicyRow("STAFF", "BRANCH"));
    }

    @Test
    void normalizesLegacyAllWithoutRegrantingADeletedPermission() {
        assertThat(inventoryScopesFor(SUPER_ASSIGNMENT)).containsExactly("ALL");
        assertThat(inventoryScopesFor(CTV_ASSIGNMENT)).containsExactly("ALL");
        assertThat(inventoryScopesFor(MANAGER_ASSIGNMENT)).containsExactly("ASSIGNED");
        assertThat(inventoryScopesFor(RECEPTIONIST_ASSIGNMENT)).containsExactly("ASSIGNED");
        assertThat(inventoryScopesFor(STAFF_ASSIGNMENT)).containsExactly("ASSIGNED");
        assertThat(inventoryScopesFor(NULL_BRANCH_ASSIGNMENT)).containsExactly("ASSIGNED");
        assertThat(inventoryScopesFor(REDUCED_STAFF_ASSIGNMENT)).isEmpty();

        assertThat(inventoryPartitionsFor(MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("BRANCH", MANAGER_BRANCH));
        assertThat(inventoryPartitionsFor(RECEPTIONIST_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("BRANCH", RECEPTIONIST_BRANCH));
        assertThat(inventoryPartitionsFor(STAFF_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("BRANCH", STAFF_BRANCH));
        assertThat(inventoryPartitionsFor(NULL_BRANCH_ASSIGNMENT)).isEmpty();
        assertThat(inventoryPartitionsFor(REDUCED_STAFF_ASSIGNMENT)).isEmpty();
        assertThat(inventoryPartitionsFor(SUPER_ASSIGNMENT)).isEmpty();
        assertThat(inventoryPartitionsFor(CTV_ASSIGNMENT)).isEmpty();

        assertThat(authorizationVersion(SUPER_SUBJECT)).isEqualTo(20);
        assertThat(authorizationVersion(CTV_SUBJECT)).isEqualTo(20);
        assertThat(authorizationVersion(MANAGER_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(RECEPTIONIST_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(STAFF_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(NULL_BRANCH_SUBJECT)).isEqualTo(21);
        assertThat(authorizationVersion(REDUCED_STAFF_SUBJECT)).isEqualTo(20);
    }

    @Test
    void synchronizesNewRevokedReinstatedAndMovedAssignmentsWithoutDoubleBumps() {
        var manager = insertNewOperationalAssignment("MANAGER", UUID.randomUUID());
        var receptionist = insertNewOperationalAssignment("RECEPTIONIST", UUID.randomUUID());
        var staff = insertNewOperationalAssignment("STAFF", UUID.randomUUID());

        for (var fixture : List.of(manager, receptionist, staff)) {
            assertThat(inventoryScopesFor(fixture.assignmentId())).containsExactly("ASSIGNED");
            assertThat(inventoryPartitionsFor(fixture.assignmentId())).containsExactly(
                new PartitionBindingRow("BRANCH", fixture.branchId()));
        }

        var movedManagerBranch = UUID.randomUUID();
        var managerVersion = authorizationVersion(manager.subjectId());
        updateBranch(manager.subjectId(), movedManagerBranch);
        assertThat(inventoryPartitionsFor(manager.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", movedManagerBranch));
        assertThat(authorizationVersion(manager.subjectId())).isEqualTo(managerVersion + 1);

        var movedReceptionistBranch = UUID.randomUUID();
        var receptionistVersion = authorizationVersion(receptionist.subjectId());
        updateBranch(receptionist.subjectId(), movedReceptionistBranch);
        assertThat(inventoryPartitionsFor(receptionist.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", movedReceptionistBranch));
        assertThat(authorizationVersion(receptionist.subjectId()))
            .isEqualTo(receptionistVersion + 1);

        revokeAssignment(receptionist.assignmentId());
        assertThat(inventoryPartitionsFor(receptionist.assignmentId())).isEmpty();
        assertThat(inventoryScopesFor(receptionist.assignmentId())).containsExactly("ASSIGNED");

        reinstateAssignment(receptionist.assignmentId());
        assertThat(inventoryPartitionsFor(receptionist.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", movedReceptionistBranch));

        deleteInventoryScope(staff.assignmentId());
        assertThat(inventoryPartitionsFor(staff.assignmentId())).isEmpty();
        var reducedVersion = authorizationVersion(staff.subjectId());
        updateBranch(staff.subjectId(), UUID.randomUUID());
        assertThat(inventoryScopesFor(staff.assignmentId())).isEmpty();
        assertThat(inventoryPartitionsFor(staff.assignmentId())).isEmpty();
        assertThat(authorizationVersion(staff.subjectId())).isEqualTo(reducedVersion);

        revokeAssignment(staff.assignmentId());
        reinstateAssignment(staff.assignmentId());
        assertThat(inventoryScopesFor(staff.assignmentId())).isEmpty();
        assertThat(inventoryPartitionsFor(staff.assignmentId())).isEmpty();
    }

    @Test
    void rejectsPolicyScopeAndPartitionEscalationOnInsertAndUpdate() {
        for (var role : BRANCH_ROLES) {
            assertThatThrownBy(() -> insertRoleScopePolicy(role, "ALL"))
                .as("ALL role policy insert for %s", role)
                .isInstanceOf(DataAccessException.class);
            assertThatThrownBy(() -> insertRolePartitionPolicy(role, "AREA"))
                .as("AREA partition policy insert for %s", role)
                .isInstanceOf(DataAccessException.class);
        }

        assertThatThrownBy(() -> jdbc.sql("""
                UPDATE role_permission_policies rpp
                SET scope_type = 'ALL'
                FROM roles r, permissions p
                WHERE rpp.role_id = r.id
                  AND rpp.permission_id = p.id
                  AND r.code = 'MANAGER'
                  AND p.code = 'inventory:read'
                  AND rpp.scope_type = 'ASSIGNED'
                """).update())
            .as("ALL role policy update")
            .isInstanceOf(DataAccessException.class);

        assertThatThrownBy(() -> jdbc.sql("""
                UPDATE role_permission_partition_policies rpp
                SET partition_type = 'AREA'
                FROM roles r, permissions p
                WHERE rpp.role_id = r.id
                  AND rpp.permission_id = p.id
                  AND r.code = 'MANAGER'
                  AND p.code = 'inventory:read'
                  AND rpp.partition_type = 'BRANCH'
                """).update())
            .as("AREA partition policy update")
            .isInstanceOf(DataAccessException.class);

        var fixture = insertNewOperationalAssignment("MANAGER", UUID.randomUUID());
        assertThatThrownBy(() -> insertInventoryScope(fixture.assignmentId(), "ALL"))
            .as("ALL subject scope insert")
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.sql("""
                UPDATE subject_role_permission_scopes srps
                SET scope_type = 'ALL'
                FROM permissions p
                WHERE srps.assignment_id = :assignmentId
                  AND srps.permission_id = p.id
                  AND p.code = 'inventory:read'
                  AND srps.scope_type = 'ASSIGNED'
                """)
            .param("assignmentId", fixture.assignmentId())
            .update())
            .as("ALL subject scope update")
            .isInstanceOf(DataAccessException.class);

        assertThatThrownBy(() -> jdbc.sql("""
                UPDATE subject_role_permission_partitions srpp
                SET partition_id = :foreignBranch
                FROM permissions p
                WHERE srpp.assignment_id = :assignmentId
                  AND srpp.permission_id = p.id
                  AND p.code = 'inventory:read'
                  AND srpp.partition_type = 'BRANCH'
                """)
            .param("assignmentId", fixture.assignmentId())
            .param("foreignBranch", UUID.randomUUID())
            .update())
            .as("foreign subject partition update")
            .isInstanceOf(DataAccessException.class);
    }

    @Test
    void rejectsNullForeignAreaOrphanAndRevokedSubjectPartitions() {
        var fixture = insertNewOperationalAssignment("RECEPTIONIST", UUID.randomUUID());

        assertThatThrownBy(() -> insertInventoryPartition(
            fixture.assignmentId(), "BRANCH", UUID.randomUUID()))
            .as("foreign BRANCH")
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> insertInventoryPartition(
            fixture.assignmentId(), "AREA", fixture.branchId()))
            .as("AREA partition")
            .isInstanceOf(DataAccessException.class);

        deleteInventoryScope(fixture.assignmentId());
        assertThatThrownBy(() -> insertInventoryPartition(
            fixture.assignmentId(), "BRANCH", fixture.branchId()))
            .as("orphan partition without ASSIGNED")
            .isInstanceOf(DataAccessException.class);

        insertInventoryScope(fixture.assignmentId(), "ASSIGNED");
        revokeAssignment(fixture.assignmentId());
        assertThatThrownBy(() -> insertInventoryPartition(
            fixture.assignmentId(), "BRANCH", fixture.branchId()))
            .as("partition on revoked assignment")
            .isInstanceOf(DataAccessException.class);

        var nullBranch = insertNewOperationalAssignment("STAFF", null);
        assertThat(inventoryScopesFor(nullBranch.assignmentId())).containsExactly("ASSIGNED");
        assertThat(inventoryPartitionsFor(nullBranch.assignmentId())).isEmpty();
        assertThatThrownBy(() -> insertInventoryPartition(
            nullBranch.assignmentId(), "BRANCH", UUID.randomUUID()))
            .as("partition for null current branch")
            .isInstanceOf(DataAccessException.class);
    }

    @Test
    void rejectsMovingAnAssignmentIdentityWithItsExistingBranchEvidence() {
        var source = insertNewOperationalAssignment("STAFF", UUID.randomUUID());
        var target = insertNewOperationalAssignment("RECEPTIONIST", UUID.randomUUID());

        assertThatThrownBy(() -> jdbc.sql("""
                UPDATE subject_role_assignments
                SET subject_id = :targetSubjectId
                WHERE id = :assignmentId
                """)
            .param("targetSubjectId", target.subjectId())
            .param("assignmentId", source.assignmentId())
            .update())
            .as("moving a branch-bound assignment to a foreign subject")
            .isInstanceOf(DataAccessException.class);

        assertThatThrownBy(() -> jdbc.sql("""
                UPDATE subject_role_assignments sra
                SET role_id = r.id
                FROM roles r
                WHERE sra.id = :assignmentId
                  AND r.code = 'CTV'
                """)
            .param("assignmentId", source.assignmentId())
            .update())
            .as("changing the role to bypass inventory guards")
            .isInstanceOf(DataAccessException.class);

        assertThat(inventoryPartitionsFor(source.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", source.branchId()));
    }

    @Test
    void serializesAConcurrentPartitionWriteWithBranchMovement() throws Exception {
        var fixture = insertNewOperationalAssignment("RECEPTIONIST", UUID.randomUUID());
        var movedBranch = UUID.randomUUID();
        jdbc.sql("""
                DELETE FROM subject_role_permission_partitions srpp
                USING permissions p
                WHERE srpp.assignment_id = :assignmentId
                  AND srpp.permission_id = p.id
                  AND p.code = 'inventory:read'
                """)
            .param("assignmentId", fixture.assignmentId())
            .update();

        var partitionInserted = new CountDownLatch(1);
        var releasePartitionTransaction = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var partitionWrite = executor.submit(() -> {
                try (var connection = dataSource.getConnection()) {
                    connection.setAutoCommit(false);
                    insertInventoryPartition(
                        connection,
                        fixture.assignmentId(),
                        "BRANCH",
                        fixture.branchId()
                    );
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
                    updateBranch(connection, fixture.subjectId(), movedBranch);
                    connection.commit();
                }
                return null;
            });

            try {
                assertThatThrownBy(() -> branchMove.get(500, TimeUnit.MILLISECONDS))
                    .as("branch synchronization waits for the subject inventory lock")
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

        assertThat(inventoryPartitionsFor(fixture.assignmentId())).containsExactly(
            new PartitionBindingRow("BRANCH", movedBranch));
    }

    private static org.flywaydb.core.api.configuration.FluentConfiguration flyway(
        DriverManagerDataSource dataSource
    ) {
        return Flyway.configure()
            .dataSource(dataSource)
            .defaultSchema("app")
            .schemas("app")
            .locations("classpath:db/migration");
    }

    private static void seedLegacyAssignments() {
        insertAdmin(SUPER_SUBJECT, "ADMIN", null, "Legacy Super Admin");
        insertAdmin(CTV_SUBJECT, "CTV", null, "Legacy CTV");
        insertAdmin(MANAGER_SUBJECT, "MANAGER", MANAGER_BRANCH, "Legacy Manager");
        insertAdmin(
            RECEPTIONIST_SUBJECT,
            "RECEPTIONIST",
            RECEPTIONIST_BRANCH,
            "Legacy Receptionist"
        );
        insertAdmin(STAFF_SUBJECT, "STAFF", STAFF_BRANCH, "Legacy Staff");
        insertAdmin(NULL_BRANCH_SUBJECT, "MANAGER", null, "Legacy Null Branch Manager");
        insertAdmin(
            REDUCED_STAFF_SUBJECT,
            "STAFF",
            REDUCED_STAFF_BRANCH,
            "Legacy Reduced Staff"
        );

        insertAssignment(SUPER_ASSIGNMENT, SUPER_SUBJECT, "SUPER_ADMIN");
        insertAssignment(CTV_ASSIGNMENT, CTV_SUBJECT, "CTV");
        insertAssignment(MANAGER_ASSIGNMENT, MANAGER_SUBJECT, "MANAGER");
        insertAssignment(RECEPTIONIST_ASSIGNMENT, RECEPTIONIST_SUBJECT, "RECEPTIONIST");
        insertAssignment(STAFF_ASSIGNMENT, STAFF_SUBJECT, "STAFF");
        insertAssignment(NULL_BRANCH_ASSIGNMENT, NULL_BRANCH_SUBJECT, "MANAGER");
        insertAssignment(REDUCED_STAFF_ASSIGNMENT, REDUCED_STAFF_SUBJECT, "STAFF");

        insertInventoryScope(SUPER_ASSIGNMENT, "ALL");
        insertInventoryScope(CTV_ASSIGNMENT, "ALL");
        insertInventoryScope(MANAGER_ASSIGNMENT, "ALL");
        insertInventoryScope(RECEPTIONIST_ASSIGNMENT, "ALL");
        insertInventoryScope(STAFF_ASSIGNMENT, "ALL");
        insertInventoryScope(NULL_BRANCH_ASSIGNMENT, "ALL");

        insertInventoryPartition(MANAGER_ASSIGNMENT, "AREA", STALE_BRANCH);
        insertInventoryPartition(MANAGER_ASSIGNMENT, "BRANCH", STALE_BRANCH);
        for (var role : BRANCH_ROLES) {
            insertRolePartitionPolicy(role, "AREA");
        }
    }

    private static OperationalFixture insertNewOperationalAssignment(String role, UUID branchId) {
        var subjectId = UUID.randomUUID();
        var assignmentId = UUID.randomUUID();
        insertAdmin(subjectId, role, branchId, "Lifecycle " + role);
        insertAssignment(assignmentId, subjectId, role);
        return new OperationalFixture(subjectId, assignmentId, branchId);
    }

    private static void insertAdmin(
        UUID subjectId,
        String userType,
        UUID branchId,
        String fullName
    ) {
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

    private static void insertInventoryScope(UUID assignmentId, String scopeType) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_scopes(
                    assignment_id, permission_id, scope_type)
                SELECT :assignmentId, id, :scopeType
                FROM permissions
                WHERE code = 'inventory:read'
                """)
            .param("assignmentId", assignmentId)
            .param("scopeType", scopeType)
            .update();
    }

    private static void insertInventoryPartition(
        UUID assignmentId,
        String partitionType,
        UUID partitionId
    ) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_partitions(
                    assignment_id, permission_id, partition_type, partition_id)
                SELECT :assignmentId, id, :partitionType, :partitionId
                FROM permissions
                WHERE code = 'inventory:read'
                """)
            .param("assignmentId", assignmentId)
            .param("partitionType", partitionType)
            .param("partitionId", partitionId)
            .update();
    }

    private static void insertInventoryPartition(
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
                WHERE code = 'inventory:read'
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
                JOIN permissions p ON p.code = 'inventory:read'
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
                JOIN permissions p ON p.code = 'inventory:read'
                WHERE r.code = :role
                """)
            .param("role", role)
            .param("partitionType", partitionType)
            .update();
    }

    private static void deleteInventoryScope(UUID assignmentId) {
        jdbc.sql("""
                DELETE FROM subject_role_permission_scopes srps
                USING permissions p
                WHERE srps.assignment_id = :assignmentId
                  AND srps.permission_id = p.id
                  AND p.code = 'inventory:read'
                  AND srps.scope_type = 'ASSIGNED'
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
                SET revoked_at = now(), revoke_reason = 'Inventory scope lifecycle test'
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

    private static List<String> inventoryScopesFor(UUID assignmentId) {
        return jdbc.sql("""
                SELECT srps.scope_type
                FROM subject_role_permission_scopes srps
                JOIN permissions p ON p.id = srps.permission_id
                WHERE srps.assignment_id = :assignmentId
                  AND p.code = 'inventory:read'
                ORDER BY srps.scope_type
                """)
            .param("assignmentId", assignmentId)
            .query(String.class)
            .list();
    }

    private static List<PartitionBindingRow> inventoryPartitionsFor(UUID assignmentId) {
        return jdbc.sql("""
                SELECT srpp.partition_type, srpp.partition_id
                FROM subject_role_permission_partitions srpp
                JOIN permissions p ON p.id = srpp.permission_id
                WHERE srpp.assignment_id = :assignmentId
                  AND p.code = 'inventory:read'
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
