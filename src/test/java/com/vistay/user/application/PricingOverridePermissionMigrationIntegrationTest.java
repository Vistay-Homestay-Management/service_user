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
class PricingOverridePermissionMigrationIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18.6-alpine")
        .withDatabaseName("vistay_user_pricing_override_migration_test")
        .withUsername("vistay")
        .withPassword("vistay");

    private static final UUID SUPER_SUBJECT = UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID MANAGER_SUBJECT = UUID.fromString("10000000-0000-4000-8000-000000000002");
    private static final UUID MANAGER_WITHOUT_BRANCH_SUBJECT = UUID.fromString("10000000-0000-4000-8000-000000000003");
    private static final UUID RECEPTIONIST_SUBJECT = UUID.fromString("10000000-0000-4000-8000-000000000004");
    private static final UUID CTV_SUBJECT = UUID.fromString("10000000-0000-4000-8000-000000000005");
    private static final UUID STAFF_SUBJECT = UUID.fromString("10000000-0000-4000-8000-000000000006");
    private static final UUID HOST_SUBJECT = UUID.fromString("10000000-0000-4000-8000-000000000007");
    private static final UUID LIFECYCLE_MANAGER_SUBJECT =
        UUID.fromString("10000000-0000-4000-8000-000000000008");

    private static final UUID SUPER_ASSIGNMENT = UUID.fromString("20000000-0000-4000-8000-000000000001");
    private static final UUID MANAGER_ASSIGNMENT = UUID.fromString("20000000-0000-4000-8000-000000000002");
    private static final UUID MANAGER_WITHOUT_BRANCH_ASSIGNMENT = UUID.fromString("20000000-0000-4000-8000-000000000003");
    private static final UUID RECEPTIONIST_ASSIGNMENT = UUID.fromString("20000000-0000-4000-8000-000000000004");
    private static final UUID CTV_ASSIGNMENT = UUID.fromString("20000000-0000-4000-8000-000000000005");
    private static final UUID STAFF_ASSIGNMENT = UUID.fromString("20000000-0000-4000-8000-000000000006");
    private static final UUID HOST_ASSIGNMENT = UUID.fromString("20000000-0000-4000-8000-000000000007");
    private static final UUID LIFECYCLE_MANAGER_ASSIGNMENT =
        UUID.fromString("20000000-0000-4000-8000-000000000008");
    private static final UUID MANAGER_BRANCH = UUID.fromString("30000000-0000-4000-8000-000000000001");
    private static final UUID LIFECYCLE_MANAGER_BRANCH =
        UUID.fromString("30000000-0000-4000-8000-000000000002");
    private static final UUID UPDATED_LIFECYCLE_MANAGER_BRANCH =
        UUID.fromString("30000000-0000-4000-8000-000000000003");

    private static JdbcClient jdbc;

    @BeforeAll
    static void migrateAroundExistingAssignments() {
        var separator = POSTGRES.getJdbcUrl().contains("?") ? "&" : "?";
        var dataSource = new DriverManagerDataSource(
            POSTGRES.getJdbcUrl() + separator + "currentSchema=app,extensions,public",
            POSTGRES.getUsername(), POSTGRES.getPassword());

        flyway(dataSource).target("7").load().migrate();
        jdbc = JdbcClient.create(dataSource);
        seedExistingAssignments();
        flyway(dataSource).load().migrate();
    }

    @Test
    void createsTheExactActivePermissionCatalogAndOnlyTheIntendedRoleGrants() {
        var permissions = jdbc.sql("""
                SELECT code
                FROM permissions
                WHERE code IN ('pricing:override', 'pricing:approve-large-override')
                  AND active
                ORDER BY code
                """)
            .query(String.class)
            .list();
        assertThat(permissions).containsExactly(
            "pricing:approve-large-override", "pricing:override");

        var grants = jdbc.sql("""
                SELECT r.code AS role_code, p.code AS permission_code
                FROM role_permissions rp
                JOIN roles r ON r.id = rp.role_id
                JOIN permissions p ON p.id = rp.permission_id
                WHERE p.code IN ('pricing:override', 'pricing:approve-large-override')
                ORDER BY r.code, p.code
                """)
            .query(RolePermissionRow.class)
            .list();

        assertThat(grants).containsExactly(
            new RolePermissionRow("MANAGER", "pricing:override"),
            new RolePermissionRow("SUPER_ADMIN", "pricing:approve-large-override"),
            new RolePermissionRow("SUPER_ADMIN", "pricing:override"));
        assertThat(grants).extracting(RolePermissionRow::roleCode)
            .doesNotContain("RECEPTIONIST", "CTV", "HOST_PARTNER", "STAFF");
    }

    @Test
    void createsAllForSuperAdminAndAssignedPlusAllowedBranchForManager() {
        var policies = jdbc.sql("""
                SELECT r.code AS role_code, p.code AS permission_code,
                       rpp.scope_type, rpp.default_scope
                FROM role_permission_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                JOIN permissions p ON p.id = rpp.permission_id
                WHERE p.code IN ('pricing:override', 'pricing:approve-large-override')
                ORDER BY r.code, p.code, rpp.scope_type
                """)
            .query(ScopePolicyRow.class)
            .list();

        assertThat(policies).containsExactly(
            new ScopePolicyRow("MANAGER", "pricing:override", "ASSIGNED", true),
            new ScopePolicyRow("SUPER_ADMIN", "pricing:approve-large-override", "ALL", true),
            new ScopePolicyRow("SUPER_ADMIN", "pricing:override", "ALL", true));

        var partitionPolicies = jdbc.sql("""
                SELECT r.code AS role_code, p.code AS permission_code, rpp.partition_type
                FROM role_permission_partition_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                JOIN permissions p ON p.id = rpp.permission_id
                WHERE p.code IN ('pricing:override', 'pricing:approve-large-override')
                ORDER BY r.code, p.code, rpp.partition_type
                """)
            .query(PartitionPolicyRow.class)
            .list();

        assertThat(partitionPolicies).containsExactly(
            new PartitionPolicyRow("MANAGER", "pricing:override", "BRANCH"));

        assertThatThrownBy(() -> jdbc.sql("""
                INSERT INTO role_permission_policies(
                    role_id, permission_id, scope_type, default_scope)
                SELECT r.id, p.id, 'ALL', false
                FROM roles r
                JOIN permissions p ON p.code = 'pricing:override'
                WHERE r.code = 'MANAGER'
                """).update())
            .isInstanceOf(DataAccessException.class);
    }

    @Test
    void backfillsExistingAssignmentsWithoutGrantingOtherRoles() {
        assertThat(scopesFor(SUPER_ASSIGNMENT)).containsExactly(
            "pricing:approve-large-override:ALL", "pricing:override:ALL");
        assertThat(scopesFor(MANAGER_ASSIGNMENT)).containsExactly("pricing:override:ASSIGNED");
        assertThat(scopesFor(MANAGER_WITHOUT_BRANCH_ASSIGNMENT))
            .containsExactly("pricing:override:ASSIGNED");

        assertThat(scopesFor(RECEPTIONIST_ASSIGNMENT)).isEmpty();
        assertThat(scopesFor(CTV_ASSIGNMENT)).isEmpty();
        assertThat(scopesFor(STAFF_ASSIGNMENT)).isEmpty();
        assertThat(scopesFor(HOST_ASSIGNMENT)).isEmpty();

        var managerPartitions = partitionsFor(MANAGER_ASSIGNMENT);
        assertThat(managerPartitions).containsExactly(
            new PartitionBindingRow("pricing:override", "BRANCH", MANAGER_BRANCH));
        assertThat(partitionsFor(MANAGER_WITHOUT_BRANCH_ASSIGNMENT)).isEmpty();
        assertThat(partitionsFor(RECEPTIONIST_ASSIGNMENT)).isEmpty();
        assertThat(partitionsFor(CTV_ASSIGNMENT)).isEmpty();
        assertThat(partitionsFor(HOST_ASSIGNMENT)).isEmpty();
    }

    @Test
    void incrementsOnlySubjectsWhoseEffectiveAssignmentsGainPermissions() {
        // V8 adds the override permissions. V10 repairs SUPER_ADMIN's complete
        // catalog but deliberately does not grant missing legacy MANAGER
        // pricing permissions because their absence may be a prior reduction.
        assertThat(authorizationVersion(SUPER_SUBJECT)).isEqualTo(12);
        assertThat(authorizationVersion(MANAGER_SUBJECT)).isEqualTo(11);
        assertThat(authorizationVersion(MANAGER_WITHOUT_BRANCH_SUBJECT)).isEqualTo(11);

        assertThat(authorizationVersion(RECEPTIONIST_SUBJECT)).isEqualTo(10);
        assertThat(authorizationVersion(CTV_SUBJECT)).isEqualTo(10);
        assertThat(authorizationVersion(STAFF_SUBJECT)).isEqualTo(10);
        assertThat(authorizationVersion(HOST_SUBJECT)).isEqualTo(10);
    }

    @Test
    void synchronizesNewManagerGrantBranchChangesAndRevocationWithoutAllScope() {
        insertAdmin(
            LIFECYCLE_MANAGER_SUBJECT,
            "MANAGER",
            LIFECYCLE_MANAGER_BRANCH,
            "Future Branch Manager"
        );
        var versionBeforeBranchChange = authorizationVersion(LIFECYCLE_MANAGER_SUBJECT);

        insertAssignment(
            LIFECYCLE_MANAGER_ASSIGNMENT,
            LIFECYCLE_MANAGER_SUBJECT,
            "MANAGER"
        );

        assertThat(scopesFor(LIFECYCLE_MANAGER_ASSIGNMENT))
            .containsExactly("pricing:override:ASSIGNED");
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow(
                "pricing:override",
                "BRANCH",
                LIFECYCLE_MANAGER_BRANCH
            )
        );

        assertThatThrownBy(() -> jdbc.sql("""
                INSERT INTO subject_role_permission_scopes(
                    assignment_id, permission_id, scope_type)
                SELECT :assignmentId, p.id, 'ALL'
                FROM permissions p
                WHERE p.code = 'pricing:override'
                """)
            .param("assignmentId", LIFECYCLE_MANAGER_ASSIGNMENT)
            .update())
            .isInstanceOf(DataAccessException.class);

        jdbc.sql("""
                DELETE FROM subject_role_permission_scopes srps
                USING permissions p
                WHERE srps.assignment_id = :assignmentId
                  AND srps.permission_id = p.id
                  AND p.code = 'pricing:override'
                """)
            .param("assignmentId", LIFECYCLE_MANAGER_ASSIGNMENT)
            .update();
        assertThat(scopesFor(LIFECYCLE_MANAGER_ASSIGNMENT)).isEmpty();
        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).isEmpty();

        jdbc.sql("""
                UPDATE admin_users
                SET branch_reference_id = :branchId
                WHERE authorization_subject_id = :subjectId
                """)
            .param("branchId", UPDATED_LIFECYCLE_MANAGER_BRANCH)
            .param("subjectId", LIFECYCLE_MANAGER_SUBJECT)
            .update();

        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).isEmpty();

        jdbc.sql("""
                INSERT INTO subject_role_permission_scopes(
                    assignment_id, permission_id, scope_type)
                SELECT :assignmentId, p.id, 'ASSIGNED'
                FROM permissions p
                WHERE p.code = 'pricing:override'
                """)
            .param("assignmentId", LIFECYCLE_MANAGER_ASSIGNMENT)
            .update();

        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).containsExactly(
            new PartitionBindingRow(
                "pricing:override",
                "BRANCH",
                UPDATED_LIFECYCLE_MANAGER_BRANCH
            )
        );
        assertThat(authorizationVersion(LIFECYCLE_MANAGER_SUBJECT))
            .isEqualTo(versionBeforeBranchChange + 1);

        jdbc.sql("""
                UPDATE subject_role_assignments
                SET revoked_at = now(), revoke_reason = 'Integration lifecycle test'
                WHERE id = :assignmentId
                """)
            .param("assignmentId", LIFECYCLE_MANAGER_ASSIGNMENT)
            .update();

        assertThat(partitionsFor(LIFECYCLE_MANAGER_ASSIGNMENT)).isEmpty();
        assertThat(scopesFor(LIFECYCLE_MANAGER_ASSIGNMENT))
            .containsExactly("pricing:override:ASSIGNED");
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

    private static void seedExistingAssignments() {
        insertAdmin(SUPER_SUBJECT, "ADMIN", null, "Existing Super Admin");
        insertAdmin(MANAGER_SUBJECT, "MANAGER", MANAGER_BRANCH, "Existing Branch Manager");
        insertAdmin(MANAGER_WITHOUT_BRANCH_SUBJECT, "MANAGER", null, "Existing Manager Without Branch");
        insertAdmin(RECEPTIONIST_SUBJECT, "RECEPTIONIST", MANAGER_BRANCH, "Existing Receptionist");
        insertAdmin(CTV_SUBJECT, "CTV", MANAGER_BRANCH, "Existing CTV");
        insertAdmin(STAFF_SUBJECT, "STAFF", MANAGER_BRANCH, "Existing Staff");
        insertHost();

        insertAssignment(SUPER_ASSIGNMENT, SUPER_SUBJECT, "SUPER_ADMIN");
        insertAssignment(MANAGER_ASSIGNMENT, MANAGER_SUBJECT, "MANAGER");
        insertAssignment(MANAGER_WITHOUT_BRANCH_ASSIGNMENT, MANAGER_WITHOUT_BRANCH_SUBJECT, "MANAGER");
        insertAssignment(RECEPTIONIST_ASSIGNMENT, RECEPTIONIST_SUBJECT, "RECEPTIONIST");
        insertAssignment(CTV_ASSIGNMENT, CTV_SUBJECT, "CTV");
        insertAssignment(STAFF_ASSIGNMENT, STAFF_SUBJECT, "STAFF");
        insertAssignment(HOST_ASSIGNMENT, HOST_SUBJECT, "HOST_PARTNER");
    }

    private static void insertAdmin(UUID subjectId, String userType, UUID branchId, String name) {
        var accountId = UUID.randomUUID();
        var profileId = UUID.randomUUID();
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
            .param("profileId", profileId)
            .param("name", name)
            .param("userType", userType)
            .param("branchId", branchId)
            .update();
    }

    private static void insertHost() {
        var accountId = UUID.randomUUID();
        jdbc.sql("""
                INSERT INTO authorization_subjects(
                    id, account_type, auth_account_id, authorization_version)
                VALUES (:subjectId, 'HOST', :accountId, 10);
                INSERT INTO hosts(
                    id, auth_account_id, authorization_subject_id, full_name)
                VALUES (:profileId, :accountId, :subjectId, 'Existing Host');
                """)
            .param("subjectId", HOST_SUBJECT)
            .param("accountId", accountId)
            .param("profileId", UUID.randomUUID())
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

    private static List<String> scopesFor(UUID assignmentId) {
        return jdbc.sql("""
                SELECT p.code || ':' || srps.scope_type
                FROM subject_role_permission_scopes srps
                JOIN permissions p ON p.id = srps.permission_id
                WHERE srps.assignment_id = :assignmentId
                  AND p.code IN ('pricing:override', 'pricing:approve-large-override')
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
                  AND p.code IN ('pricing:override', 'pricing:approve-large-override')
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

    private record RolePermissionRow(String roleCode, String permissionCode) {}

    private record ScopePolicyRow(
        String roleCode,
        String permissionCode,
        String scopeType,
        boolean defaultScope
    ) {}

    private record PartitionPolicyRow(String roleCode, String permissionCode, String partitionType) {}

    private record PartitionBindingRow(String permissionCode, String partitionType, UUID partitionId) {}
}
