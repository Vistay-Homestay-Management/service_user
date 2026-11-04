package com.vistay.user.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.UUID;
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
class PricingManagementScopeMigrationIntegrationTest {

    private static final List<String> PRICING_PERMISSIONS = List.of(
        "pricing:approve", "pricing:read", "pricing:update");

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_user_pricing_management_scope_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static final UUID SUPER_SUBJECT = UUID.fromString("11000000-0000-4000-8000-000000000001");
    private static final UUID MANAGER_SUBJECT = UUID.fromString("11000000-0000-4000-8000-000000000002");
    private static final UUID MANAGER_WITHOUT_BRANCH_SUBJECT =
        UUID.fromString("11000000-0000-4000-8000-000000000003");
    private static final UUID RECEPTIONIST_SUBJECT =
        UUID.fromString("11000000-0000-4000-8000-000000000004");
    private static final UUID LIFECYCLE_MANAGER_SUBJECT =
        UUID.fromString("11000000-0000-4000-8000-000000000005");
    private static final UUID REDUCED_MANAGER_SUBJECT =
        UUID.fromString("11000000-0000-4000-8000-000000000006");

    private static final UUID SUPER_ASSIGNMENT = UUID.fromString("21000000-0000-4000-8000-000000000001");
    private static final UUID MANAGER_ASSIGNMENT = UUID.fromString("21000000-0000-4000-8000-000000000002");
    private static final UUID MANAGER_WITHOUT_BRANCH_ASSIGNMENT =
        UUID.fromString("21000000-0000-4000-8000-000000000003");
    private static final UUID RECEPTIONIST_ASSIGNMENT =
        UUID.fromString("21000000-0000-4000-8000-000000000004");
    private static final UUID LIFECYCLE_MANAGER_ASSIGNMENT =
        UUID.fromString("21000000-0000-4000-8000-000000000005");
    private static final UUID REDUCED_MANAGER_ASSIGNMENT =
        UUID.fromString("21000000-0000-4000-8000-000000000006");

    private static final UUID MANAGER_BRANCH = UUID.fromString("31000000-0000-4000-8000-000000000001");
    private static final UUID STALE_MANAGER_BRANCH =
        UUID.fromString("31000000-0000-4000-8000-000000000002");
    private static final UUID LIFECYCLE_MANAGER_BRANCH =
        UUID.fromString("31000000-0000-4000-8000-000000000003");
    private static final UUID UPDATED_LIFECYCLE_MANAGER_BRANCH =
        UUID.fromString("31000000-0000-4000-8000-000000000004");
    private static final UUID REDUCED_MANAGER_BRANCH =
        UUID.fromString("31000000-0000-4000-8000-000000000005");

    private static JdbcClient jdbc;

    @BeforeAll
    static void migrateAroundLegacyManagerScopes() {
        var separator = POSTGRES.getJdbcUrl().contains("?") ? "&" : "?";
        var dataSource = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl() + separator + "currentSchema=app,extensions,public",
            POSTGRES.getUsername(), POSTGRES.getPassword());

        flyway(dataSource).target("9").load().migrate();
        jdbc = JdbcClient.create(dataSource);
        seedLegacyAssignments();
        flyway(dataSource).load().migrate();
    }

    @Test
    void keepsSuperAdminAtAllAndManagerAtAssignedPlusBranchOnly() {
        var policies = jdbc.sql("""
                SELECT r.code AS role_code, p.code AS permission_code,
                       rpp.scope_type, rpp.default_scope
                FROM role_permission_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                JOIN permissions p ON p.id = rpp.permission_id
                WHERE r.code IN ('MANAGER', 'SUPER_ADMIN')
                  AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
                ORDER BY r.code, p.code, rpp.scope_type
                """)
            .query(ScopePolicyRow.class)
            .list();

        assertThat(policies).containsExactly(
            new ScopePolicyRow("MANAGER", "pricing:approve", "ASSIGNED", true),
            new ScopePolicyRow("MANAGER", "pricing:read", "ASSIGNED", true),
            new ScopePolicyRow("MANAGER", "pricing:update", "ASSIGNED", true),
            new ScopePolicyRow("SUPER_ADMIN", "pricing:approve", "ALL", true),
            new ScopePolicyRow("SUPER_ADMIN", "pricing:read", "ALL", true),
            new ScopePolicyRow("SUPER_ADMIN", "pricing:update", "ALL", true));

        var partitionPolicies = jdbc.sql("""
                SELECT r.code AS role_code, p.code AS permission_code, rpp.partition_type
                FROM role_permission_partition_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                JOIN permissions p ON p.id = rpp.permission_id
                WHERE r.code IN ('MANAGER', 'SUPER_ADMIN')
                  AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
                ORDER BY r.code, p.code, rpp.partition_type
                """)
            .query(PartitionPolicyRow.class)
            .list();

        assertThat(partitionPolicies).containsExactly(
            new PartitionPolicyRow("MANAGER", "pricing:approve", "BRANCH"),
            new PartitionPolicyRow("MANAGER", "pricing:read", "BRANCH"),
            new PartitionPolicyRow("MANAGER", "pricing:update", "BRANCH"));
    }

    @Test
    void repairsExistingAssignmentsAndInvalidatesOnlyChangedSubjects() {
        assertThat(scopesFor(SUPER_ASSIGNMENT)).containsExactly(
            "pricing:approve:ALL", "pricing:read:ALL", "pricing:update:ALL");
        assertThat(scopesFor(MANAGER_ASSIGNMENT)).containsExactly(
            "pricing:approve:ASSIGNED", "pricing:read:ASSIGNED", "pricing:update:ASSIGNED");
        assertThat(scopesFor(MANAGER_WITHOUT_BRANCH_ASSIGNMENT)).containsExactly(
            "pricing:approve:ASSIGNED", "pricing:read:ASSIGNED", "pricing:update:ASSIGNED");
        assertThat(scopesFor(REDUCED_MANAGER_ASSIGNMENT))
            .containsExactly("pricing:read:ASSIGNED");
        assertThat(scopesFor(RECEPTIONIST_ASSIGNMENT)).isEmpty();

        assertThat(partitionsFor(MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("pricing:approve", "BRANCH", MANAGER_BRANCH),
            new PartitionBindingRow("pricing:read", "BRANCH", MANAGER_BRANCH),
            new PartitionBindingRow("pricing:update", "BRANCH", MANAGER_BRANCH));
        assertThat(partitionsFor(MANAGER_WITHOUT_BRANCH_ASSIGNMENT)).isEmpty();
        assertThat(partitionsFor(REDUCED_MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("pricing:read", "BRANCH", REDUCED_MANAGER_BRANCH));
        assertThat(partitionsFor(RECEPTIONIST_ASSIGNMENT)).isEmpty();

        assertThat(authorizationVersion(SUPER_SUBJECT)).isEqualTo(11);
        assertThat(authorizationVersion(MANAGER_SUBJECT)).isEqualTo(11);
        assertThat(authorizationVersion(MANAGER_WITHOUT_BRANCH_SUBJECT)).isEqualTo(11);
        assertThat(authorizationVersion(REDUCED_MANAGER_SUBJECT)).isEqualTo(11);
        assertThat(authorizationVersion(RECEPTIONIST_SUBJECT)).isEqualTo(10);
    }

    @Test
    void rejectsDirectForeignNonBranchOrOrphanManagerPricingPartitions() {
        var subjectId = UUID.randomUUID();
        var assignmentId = UUID.randomUUID();
        var currentBranch = UUID.randomUUID();
        var foreignBranch = UUID.randomUUID();
        insertAdmin(subjectId, "MANAGER", currentBranch, "Partition Guard Manager");
        insertAssignment(assignmentId, subjectId, "MANAGER");

        assertThatThrownBy(() -> insertPartition(
            assignmentId, "pricing:read", "BRANCH", foreignBranch))
            .as("foreign branch insert")
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> insertPartition(
            assignmentId, "pricing:read", "AREA", currentBranch))
            .as("non-BRANCH insert")
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.sql("""
                UPDATE subject_role_permission_partitions srpp
                SET partition_id = :foreignBranch
                FROM permissions p
                WHERE srpp.assignment_id = :assignmentId
                  AND srpp.permission_id = p.id
                  AND p.code = 'pricing:read'
                  AND srpp.partition_type = 'BRANCH'
                """)
            .param("assignmentId", assignmentId)
            .param("foreignBranch", foreignBranch)
            .update())
            .as("foreign branch update")
            .isInstanceOf(DataAccessException.class);

        deleteScope(assignmentId, "pricing:update");
        assertThatThrownBy(() -> insertPartition(
            assignmentId, "pricing:update", "BRANCH", currentBranch))
            .as("orphan partition without ASSIGNED scope")
            .isInstanceOf(DataAccessException.class);

        jdbc.sql("""
                UPDATE subject_role_assignments
                SET revoked_at = now(), revoke_reason = 'Partition guard test'
                WHERE id = :assignmentId
                """)
            .param("assignmentId", assignmentId)
            .update();
        assertThatThrownBy(() -> insertPartition(
            assignmentId, "pricing:read", "BRANCH", currentBranch))
            .as("partition on revoked assignment")
            .isInstanceOf(DataAccessException.class);
    }

    @Test
    void rejectsManagerAllPoliciesAndAssignmentGrantsForEveryManagedPermission() {
        for (var permission : PRICING_PERMISSIONS) {
            assertThatThrownBy(() -> jdbc.sql("""
                    INSERT INTO role_permission_policies(
                        role_id, permission_id, scope_type, default_scope)
                    SELECT r.id, p.id, 'ALL', false
                    FROM roles r
                    JOIN permissions p ON p.code = :permission
                    WHERE r.code = 'MANAGER'
                    """)
                .param("permission", permission)
                .update())
                .as("role policy for %s", permission)
                .isInstanceOf(DataAccessException.class);

            assertThatThrownBy(() -> jdbc.sql("""
                    INSERT INTO subject_role_permission_scopes(
                        assignment_id, permission_id, scope_type)
                    SELECT :assignmentId, p.id, 'ALL'
                    FROM permissions p
                    WHERE p.code = :permission
                    """)
                .param("assignmentId", MANAGER_ASSIGNMENT)
                .param("permission", permission)
                .update())
                .as("assignment grant for %s", permission)
                .isInstanceOf(DataAccessException.class);
        }
    }

    @Test
    void synchronizesCreateScopeBranchRevocationAndReactivationLifecycle() {
        insertAdmin(
            LIFECYCLE_MANAGER_SUBJECT,
            "MANAGER",
            LIFECYCLE_MANAGER_BRANCH,
            "Lifecycle Branch Manager"
        );
        insertAssignment(
            LIFECYCLE_MANAGER_ASSIGNMENT,
            LIFECYCLE_MANAGER_SUBJECT,
            "MANAGER"
        );

        assertThat(scopesFor(LIFECYCLE_MANAGER_ASSIGNMENT)).containsExactly(
            "pricing:approve:ASSIGNED", "pricing:read:ASSIGNED", "pricing:update:ASSIGNED");
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("pricing:approve", "BRANCH", LIFECYCLE_MANAGER_BRANCH),
            new PartitionBindingRow("pricing:read", "BRANCH", LIFECYCLE_MANAGER_BRANCH),
            new PartitionBindingRow("pricing:update", "BRANCH", LIFECYCLE_MANAGER_BRANCH));

        deleteScope(LIFECYCLE_MANAGER_ASSIGNMENT, "pricing:update");
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("pricing:approve", "BRANCH", LIFECYCLE_MANAGER_BRANCH),
            new PartitionBindingRow("pricing:read", "BRANCH", LIFECYCLE_MANAGER_BRANCH));

        var versionBeforeBranchChange = authorizationVersion(LIFECYCLE_MANAGER_SUBJECT);
        updateBranch(LIFECYCLE_MANAGER_SUBJECT, UPDATED_LIFECYCLE_MANAGER_BRANCH);
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("pricing:approve", "BRANCH", UPDATED_LIFECYCLE_MANAGER_BRANCH),
            new PartitionBindingRow("pricing:read", "BRANCH", UPDATED_LIFECYCLE_MANAGER_BRANCH));
        assertThat(authorizationVersion(LIFECYCLE_MANAGER_SUBJECT))
            .isEqualTo(versionBeforeBranchChange + 1);

        insertAssignedScope(LIFECYCLE_MANAGER_ASSIGNMENT, "pricing:update");
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("pricing:approve", "BRANCH", UPDATED_LIFECYCLE_MANAGER_BRANCH),
            new PartitionBindingRow("pricing:read", "BRANCH", UPDATED_LIFECYCLE_MANAGER_BRANCH),
            new PartitionBindingRow("pricing:update", "BRANCH", UPDATED_LIFECYCLE_MANAGER_BRANCH));

        updateBranch(LIFECYCLE_MANAGER_SUBJECT, null);
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).isEmpty();

        updateBranch(LIFECYCLE_MANAGER_SUBJECT, UPDATED_LIFECYCLE_MANAGER_BRANCH);
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).hasSize(3);

        jdbc.sql("""
                UPDATE subject_role_assignments
                SET revoked_at = now(), revoke_reason = 'Pricing management lifecycle test'
                WHERE id = :assignmentId
                """)
            .param("assignmentId", LIFECYCLE_MANAGER_ASSIGNMENT)
            .update();
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).isEmpty();
        assertThat(scopesFor(LIFECYCLE_MANAGER_ASSIGNMENT)).hasSize(3);

        jdbc.sql("""
                UPDATE subject_role_assignments
                SET revoked_at = NULL, revoke_reason = NULL
                WHERE id = :assignmentId
                """)
            .param("assignmentId", LIFECYCLE_MANAGER_ASSIGNMENT)
            .update();
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow("pricing:approve", "BRANCH", UPDATED_LIFECYCLE_MANAGER_BRANCH),
            new PartitionBindingRow("pricing:read", "BRANCH", UPDATED_LIFECYCLE_MANAGER_BRANCH),
            new PartitionBindingRow("pricing:update", "BRANCH", UPDATED_LIFECYCLE_MANAGER_BRANCH));
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
        insertAdmin(SUPER_SUBJECT, "ADMIN", null, "Existing Super Admin");
        insertAdmin(MANAGER_SUBJECT, "MANAGER", MANAGER_BRANCH, "Existing Branch Manager");
        insertAdmin(
            MANAGER_WITHOUT_BRANCH_SUBJECT,
            "MANAGER",
            null,
            "Existing Manager Without Branch"
        );
        insertAdmin(RECEPTIONIST_SUBJECT, "RECEPTIONIST", MANAGER_BRANCH, "Existing Receptionist");
        insertAdmin(
            REDUCED_MANAGER_SUBJECT,
            "MANAGER",
            REDUCED_MANAGER_BRANCH,
            "Existing Reduced Manager"
        );

        insertAssignment(SUPER_ASSIGNMENT, SUPER_SUBJECT, "SUPER_ADMIN");
        insertAssignment(MANAGER_ASSIGNMENT, MANAGER_SUBJECT, "MANAGER");
        insertAssignment(
            MANAGER_WITHOUT_BRANCH_ASSIGNMENT,
            MANAGER_WITHOUT_BRANCH_SUBJECT,
            "MANAGER"
        );
        insertAssignment(RECEPTIONIST_ASSIGNMENT, RECEPTIONIST_SUBJECT, "RECEPTIONIST");
        insertAssignment(REDUCED_MANAGER_ASSIGNMENT, REDUCED_MANAGER_SUBJECT, "MANAGER");

        insertScopes(MANAGER_ASSIGNMENT, "ALL");
        insertScopes(MANAGER_WITHOUT_BRANCH_ASSIGNMENT, "ALL");
        insertScope(REDUCED_MANAGER_ASSIGNMENT, "pricing:read", "ALL");
        insertStalePartitions(MANAGER_ASSIGNMENT);
        jdbc.sql("""
                INSERT INTO role_permission_partition_policies(
                    role_id, permission_id, partition_type)
                SELECT r.id, p.id, 'AREA'
                FROM roles r
                JOIN permissions p ON p.code = 'pricing:read'
                WHERE r.code = 'MANAGER'
                ON CONFLICT DO NOTHING
                """).update();
    }

    private static void insertScopes(UUID assignmentId, String scope) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_scopes(
                    assignment_id, permission_id, scope_type)
                SELECT :assignmentId, p.id, :scope
                FROM permissions p
                WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
                """)
            .param("assignmentId", assignmentId)
            .param("scope", scope)
            .update();
    }

    private static void insertScope(UUID assignmentId, String permission, String scope) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_scopes(
                    assignment_id, permission_id, scope_type)
                SELECT :assignmentId, p.id, :scope
                FROM permissions p
                WHERE p.code = :permission
                """)
            .param("assignmentId", assignmentId)
            .param("permission", permission)
            .param("scope", scope)
            .update();
    }

    private static void insertPartition(
        UUID assignmentId,
        String permission,
        String partitionType,
        UUID partitionId
    ) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_partitions(
                    assignment_id, permission_id, partition_type, partition_id)
                SELECT :assignmentId, p.id, :partitionType, :partitionId
                FROM permissions p
                WHERE p.code = :permission
                """)
            .param("assignmentId", assignmentId)
            .param("permission", permission)
            .param("partitionType", partitionType)
            .param("partitionId", partitionId)
            .update();
    }

    private static void insertStalePartitions(UUID assignmentId) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_partitions(
                    assignment_id, permission_id, partition_type, partition_id)
                SELECT :assignmentId, p.id, 'AREA', :staleBranch
                FROM permissions p
                WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve');

                INSERT INTO subject_role_permission_partitions(
                    assignment_id, permission_id, partition_type, partition_id)
                SELECT :assignmentId, p.id, 'BRANCH', :staleBranch
                FROM permissions p
                WHERE p.code IN ('pricing:read', 'pricing:update', 'pricing:approve');
                """)
            .param("assignmentId", assignmentId)
            .param("staleBranch", STALE_MANAGER_BRANCH)
            .update();
    }

    private static void insertAdmin(UUID subjectId, String userType, UUID branchId, String name) {
        var accountId = UUID.randomUUID();
        jdbc.sql("""
                INSERT INTO authorization_subjects(
                    id, account_type, auth_account_id, authorization_version)
                VALUES (:subjectId, 'ADMIN', :accountId, 10);

                INSERT INTO admin_users(
                    id, auth_account_id, authorization_subject_id, full_name,
                    user_type, branch_reference_id)
                VALUES (:profileId, :accountId, :subjectId, :name, :userType, :branchId);
                """)
            .param("subjectId", subjectId)
            .param("accountId", accountId)
            .param("profileId", UUID.randomUUID())
            .param("name", name)
            .param("userType", userType)
            .param("branchId", branchId)
            .update();
    }

    private static void insertAssignment(UUID assignmentId, UUID subjectId, String roleCode) {
        jdbc.sql("""
                INSERT INTO subject_role_assignments(
                    id, subject_id, role_id, valid_from)
                SELECT :assignmentId, :subjectId, id, now() - interval '1 hour'
                FROM roles
                WHERE code = :roleCode
                """)
            .param("assignmentId", assignmentId)
            .param("subjectId", subjectId)
            .param("roleCode", roleCode)
            .update();
    }

    private static void deleteScope(UUID assignmentId, String permission) {
        jdbc.sql("""
                DELETE FROM subject_role_permission_scopes srps
                USING permissions p
                WHERE srps.assignment_id = :assignmentId
                  AND srps.permission_id = p.id
                  AND p.code = :permission
                  AND srps.scope_type = 'ASSIGNED'
                """)
            .param("assignmentId", assignmentId)
            .param("permission", permission)
            .update();
    }

    private static void insertAssignedScope(UUID assignmentId, String permission) {
        jdbc.sql("""
                INSERT INTO subject_role_permission_scopes(
                    assignment_id, permission_id, scope_type)
                SELECT :assignmentId, p.id, 'ASSIGNED'
                FROM permissions p
                WHERE p.code = :permission
                """)
            .param("assignmentId", assignmentId)
            .param("permission", permission)
            .update();
    }

    private static void updateBranch(UUID subjectId, UUID branchId) {
        jdbc.sql("""
                UPDATE admin_users
                SET branch_reference_id = :branchId
                WHERE authorization_subject_id = :subjectId
                """)
            .param("branchId", branchId)
            .param("subjectId", subjectId)
            .update();
    }

    private static List<String> scopesFor(UUID assignmentId) {
        return jdbc.sql("""
                SELECT p.code || ':' || srps.scope_type
                FROM subject_role_permission_scopes srps
                JOIN permissions p ON p.id = srps.permission_id
                WHERE srps.assignment_id = :assignmentId
                  AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
                ORDER BY p.code, srps.scope_type
                """)
            .param("assignmentId", assignmentId)
            .query(String.class)
            .list();
    }

    private static List<PartitionBindingRow> partitionsFor(UUID assignmentId) {
        return jdbc.sql("""
                SELECT p.code AS permission_code, srpp.partition_type, srpp.partition_id
                FROM subject_role_permission_partitions srpp
                JOIN permissions p ON p.id = srpp.permission_id
                WHERE srpp.assignment_id = :assignmentId
                  AND p.code IN ('pricing:read', 'pricing:update', 'pricing:approve')
                ORDER BY p.code, srpp.partition_type, srpp.partition_id
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

    private record ScopePolicyRow(
        String roleCode,
        String permissionCode,
        String scopeType,
        boolean defaultScope
    ) {}

    private record PartitionPolicyRow(String roleCode, String permissionCode, String partitionType) {}

    private record PartitionBindingRow(String permissionCode, String partitionType, UUID partitionId) {}
}
