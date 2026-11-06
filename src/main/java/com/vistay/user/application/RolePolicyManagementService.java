package com.vistay.user.application;

import graphql.GraphqlErrorException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.ObjectMapper;

@Service
public class RolePolicyManagementService {
    private static final String ROLE_POLICY_CHANGED = "vistay.user.role-policy-changed";
    private static final Pattern ROLE_CODE = Pattern.compile("^[A-Z][A-Z0-9_]{1,63}$");
    private static final Pattern PERMISSION_CODE = Pattern.compile(
        "^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$");
    private static final Set<String> ACCOUNT_TYPES = Set.of("CUSTOMER", "ADMIN", "HOST");
    private static final Set<String> SCOPES = Set.of("SELF", "OWN", "ASSIGNED", "PARTITION", "ALL");
    private static final Set<String> RESCUE_PERMISSIONS = Set.of(
        "role:read", "role:change-request", "role:change-approve");

    private final JdbcClient jdbc;
    private final ObjectMapper json;
    private final AuthorizationManagementService authorization;
    private final RolePolicyService policies;

    public RolePolicyManagementService(
        JdbcClient jdbc,
        ObjectMapper json,
        AuthorizationManagementService authorization,
        RolePolicyService policies
    ) {
        this.jdbc = jdbc;
        this.json = json;
        this.authorization = authorization;
        this.policies = policies;
    }

    public List<RoleView> catalog(UUID actorAccountId, String accountType) {
        authorization.requireActor(actorAccountId, "role:read");
        var type = normalizeAccountType(accountType);
        return jdbc.sql("""
                SELECT id, code, display_name, description, audience, system_role, active,
                       policy_version, created_at, updated_at
                FROM roles WHERE audience = :accountType
                ORDER BY active DESC, code
                """).param("accountType", type).query(RoleRow.class).list().stream()
            .map(this::view).toList();
    }

    public RoleView role(UUID actorAccountId, String accountType, String roleCode) {
        authorization.requireActor(actorAccountId, "role:read");
        return view(findRole(normalizeAccountType(accountType), normalizeRoleCode(roleCode), false));
    }

    public List<PermissionView> permissionCatalog(UUID actorAccountId) {
        authorization.requireActor(actorAccountId, "role:read");
        var permissions = jdbc.sql("""
                SELECT id, code, resource, action, description, active, deprecated_at
                FROM permissions ORDER BY active DESC, code
                """).query(PermissionRow.class).list();
        return permissions.stream().map(permission -> new PermissionView(
            permission.code(), permission.resource(), permission.action(), permission.description(),
            permission.active(), permission.deprecatedAt() == null ? null : permission.deprecatedAt().toString(),
            jdbc.sql("SELECT alias_code FROM permission_aliases WHERE permission_id = :id ORDER BY alias_code")
                .param("id", permission.id()).query(String.class).list()
        )).toList();
    }

    public List<ChangeRequestView> changeRequests(UUID actorAccountId, String status) {
        authorization.requireActor(actorAccountId, "role:read");
        expirePending();
        var normalized = status == null ? "PENDING" : status.trim().toUpperCase();
        if (!Set.of("PENDING", "APPROVED", "REJECTED", "EXPIRED", "STALE").contains(normalized)) {
            throw error("INVALID_CHANGE_STATUS", "Unsupported role-policy change status");
        }
        return jdbc.sql("""
                SELECT id, target_role_code, requested_by_subject_id, reviewed_by_subject_id,
                       change_type, status, expected_role_version, reason, review_reason,
                       expires_at, created_at
                FROM role_policy_change_requests WHERE status = :status
                ORDER BY created_at DESC
                """).param("status", normalized).query(ChangeRequestRow.class).list().stream()
            .map(ChangeRequestRow::view).toList();
    }

    @Transactional
    public ChangeRequestView requestCreate(UUID actorAccountId, CreateRoleInput input) {
        var actor = authorization.requireActor(actorAccountId, "role:change-request");
        requireReason(input.reason());
        requireIdempotencyKey(input.idempotencyKey());
        var code = normalizeRoleCode(input.code());
        var accountType = normalizeAccountType(input.accountType());
        requireDisplayName(input.displayName());
        var grants = normalizeGrants(input.grants());
        if (grants.isEmpty()) throw error("EMPTY_ROLE_POLICY", "A role must contain at least one permission");
        validatePermissions(grants);
        var payload = write(Map.of(
            "code", code, "displayName", input.displayName().trim(),
            "description", input.description() == null ? "" : input.description().trim(),
            "accountType", accountType, "grants", grants));
        return insertRequest(actor.subjectId(), null, code, "CREATE_ROLE", null,
            payload, input.reason(), input.idempotencyKey());
    }

    @Transactional
    public ChangeRequestView requestPermissionChange(UUID actorAccountId, PermissionChangeInput input) {
        var actor = authorization.requireActor(actorAccountId, "role:change-request");
        requireReason(input.reason());
        requireIdempotencyKey(input.idempotencyKey());
        var role = findRole(normalizeAccountType(input.accountType()), normalizeRoleCode(input.roleCode()), false);
        if (!role.active()) throw error("ROLE_INACTIVE", "Inactive roles cannot be changed");
        var additions = normalizeGrants(input.addGrants());
        var removals = normalizePermissionCodes(input.removePermissionCodes());
        if (additions.isEmpty() && removals.isEmpty()) {
            throw error("NO_ROLE_POLICY_CHANGE", "At least one permission change is required");
        }
        if (!java.util.Collections.disjoint(
            additions.stream().map(GrantInput::permissionCode).toList(), removals)) {
            throw error("AMBIGUOUS_ROLE_POLICY_CHANGE", "A permission cannot be added and removed together");
        }
        validatePermissions(additions);
        protectRescuePolicy(role, removals, additions);
        var payload = write(Map.of("addGrants", additions, "removePermissionCodes", removals));
        return insertRequest(actor.subjectId(), role.id(), role.code(), "CHANGE_PERMISSIONS",
            input.expectedRoleVersion(), payload, input.reason(), input.idempotencyKey());
    }

    @Transactional
    public ChangeRequestView requestDeactivate(UUID actorAccountId, DeactivateRoleInput input) {
        var actor = authorization.requireActor(actorAccountId, "role:change-request");
        requireReason(input.reason());
        requireIdempotencyKey(input.idempotencyKey());
        var role = findRole(normalizeAccountType(input.accountType()), normalizeRoleCode(input.roleCode()), false);
        if (role.systemRole()) throw error("SYSTEM_ROLE_PROTECTED", "System roles cannot be deactivated");
        if (!role.active()) throw error("ROLE_INACTIVE", "Role is already inactive");
        return insertRequest(actor.subjectId(), role.id(), role.code(), "DEACTIVATE_ROLE",
            input.expectedRoleVersion(), "{}", input.reason(), input.idempotencyKey());
    }

    @Transactional
    public ChangeRequestView approve(UUID actorAccountId, UUID requestId, String reviewReason) {
        var actor = authorization.requireActor(actorAccountId, "role:change-approve");
        requireReason(reviewReason);
        var request = lockRequest(requestId);
        requirePending(request);
        if (request.requestedBySubjectId().equals(actor.subjectId())) {
            throw error("MAKER_CHECKER_VIOLATION", "Requester cannot approve the same change");
        }

        RoleRow changed;
        try {
            changed = switch (request.changeType()) {
                case "CREATE_ROLE" -> approveCreate(request);
                case "CHANGE_PERMISSIONS" -> approvePermissionChange(request);
                case "DEACTIVATE_ROLE" -> approveDeactivate(request);
                default -> throw error("INVALID_ROLE_POLICY_PAYLOAD", "Unsupported role-policy change type");
            };
        } catch (GraphqlErrorException stale) {
            var code = stale.getExtensions() == null ? null : stale.getExtensions().get("code");
            if (Set.of("ROLE_VERSION_CONFLICT", "ROLE_ALREADY_EXISTS", "ROLE_INACTIVE").contains(code)) {
                markStale(request.id(), actor.subjectId(), reviewReason);
                return findRequest(request.id());
            }
            throw stale;
        }

        jdbc.sql("""
                UPDATE role_policy_change_requests
                SET status = 'APPROVED', reviewed_by_subject_id = :reviewer,
                    review_reason = :reason, reviewed_at = now()
                WHERE id = :id
                """).param("reviewer", actor.subjectId()).param("reason", reviewReason.trim())
            .param("id", request.id()).update();
        var catalogVersion = bumpCatalogVersion();
        reconcileCompatibilityAssignments(changed);
        emitPolicyChanged(changed, catalogVersion);
        audit(actor.subjectId(), "ROLE_POLICY_CHANGE_APPROVED", changed, reviewReason);
        evictAfterCommit(changed.audience(), changed.code());
        return findRequest(request.id());
    }

    @Transactional
    public ChangeRequestView reject(UUID actorAccountId, UUID requestId, String reviewReason) {
        var actor = authorization.requireActor(actorAccountId, "role:change-approve");
        requireReason(reviewReason);
        var request = lockRequest(requestId);
        requirePending(request);
        if (request.requestedBySubjectId().equals(actor.subjectId())) {
            throw error("MAKER_CHECKER_VIOLATION", "Requester cannot reject the same change");
        }
        jdbc.sql("""
                UPDATE role_policy_change_requests
                SET status = 'REJECTED', reviewed_by_subject_id = :reviewer,
                    review_reason = :reason, reviewed_at = now()
                WHERE id = :id
                """).param("reviewer", actor.subjectId()).param("reason", reviewReason.trim())
            .param("id", request.id()).update();
        return findRequest(request.id());
    }

    private RoleRow approveCreate(RequestRow request) {
        var root = read(request.payload());
        var code = normalizeRoleCode(root.get("code").asString());
        if (jdbc.sql("SELECT count(*) FROM roles WHERE code = :code").param("code", code)
            .query(Long.class).single() > 0) {
            throw error("ROLE_ALREADY_EXISTS", "Role code already exists");
        }
        var role = jdbc.sql("""
                INSERT INTO roles(code, display_name, description, system_role, active, audience, policy_version)
                VALUES (:code, :displayName, :description, false, true, :audience, 1)
                RETURNING id, code, display_name, description, audience, system_role, active,
                          policy_version, created_at, updated_at
                """).param("code", code).param("displayName", root.get("displayName").asString())
            .param("description", root.get("description").asString())
            .param("audience", normalizeAccountType(root.get("accountType").asString()))
            .query(RoleRow.class).single();
        applyAdditions(role.id(), parseGrants(root.get("grants")));
        jdbc.sql("UPDATE role_policy_change_requests SET target_role_id = :roleId WHERE id = :id")
            .param("roleId", role.id()).param("id", request.id()).update();
        return role;
    }

    private RoleRow approvePermissionChange(RequestRow request) {
        var role = lockRole(request.targetRoleId());
        requireVersion(role, request.expectedRoleVersion());
        if (!role.active()) throw error("ROLE_INACTIVE", "Inactive roles cannot be changed");
        var root = read(request.payload());
        var removals = new ArrayList<String>();
        root.get("removePermissionCodes").forEach(node -> removals.add(node.asString()));
        var additions = parseGrants(root.get("addGrants"));
        protectRescuePolicy(role, removals, additions);
        if (!removals.isEmpty()) {
            jdbc.sql("""
                    DELETE FROM role_permissions rp USING permissions p
                    WHERE rp.permission_id = p.id AND rp.role_id = :roleId
                      AND p.code IN (:codes)
                    """).param("roleId", role.id()).param("codes", removals).update();
        }
        applyAdditions(role.id(), additions);
        return bumpRoleVersion(role.id());
    }

    private RoleRow approveDeactivate(RequestRow request) {
        var role = lockRole(request.targetRoleId());
        requireVersion(role, request.expectedRoleVersion());
        if (role.systemRole()) throw error("SYSTEM_ROLE_PROTECTED", "System roles cannot be deactivated");
        if (!role.active()) throw error("ROLE_INACTIVE", "Role is already inactive");
        return jdbc.sql("""
                UPDATE roles SET active = false, deactivated_at = now(),
                    policy_version = policy_version + 1, updated_at = now()
                WHERE id = :id
                RETURNING id, code, display_name, description, audience, system_role, active,
                          policy_version, created_at, updated_at
                """).param("id", role.id()).query(RoleRow.class).single();
    }

    private void applyAdditions(UUID roleId, List<GrantInput> grants) {
        validatePermissions(grants);
        for (var grant : grants) {
            var permissionId = permissionId(grant.permissionCode());
            jdbc.sql("INSERT INTO role_permissions(role_id, permission_id) VALUES (:role, :permission) ON CONFLICT DO NOTHING")
                .param("role", roleId).param("permission", permissionId).update();
            jdbc.sql("DELETE FROM role_permission_policies WHERE role_id = :role AND permission_id = :permission")
                .param("role", roleId).param("permission", permissionId).update();
            for (var scope : grant.allowedScopes()) {
                jdbc.sql("""
                        INSERT INTO role_permission_policies(role_id, permission_id, scope_type, default_scope)
                        VALUES (:role, :permission, :scope, true)
                        """).param("role", roleId).param("permission", permissionId)
                    .param("scope", scope).update();
            }
            jdbc.sql("DELETE FROM role_permission_partition_types WHERE role_id = :role AND permission_id = :permission")
                .param("role", roleId).param("permission", permissionId).update();
            for (var partitionType : grant.partitionTypes()) {
                jdbc.sql("""
                        INSERT INTO role_permission_partition_types(role_id, permission_id, partition_type)
                        VALUES (:role, :permission, :partitionType)
                        """).param("role", roleId).param("permission", permissionId)
                    .param("partitionType", partitionType).update();
            }
        }
    }

    private ChangeRequestView insertRequest(UUID requester, UUID roleId, String roleCode,
        String changeType, Long expectedVersion, String payload, String reason, String idempotencyKey) {
        var hash = sha256(changeType + "\n" + roleCode + "\n" + expectedVersion + "\n" + payload);
        var existing = jdbc.sql("""
                SELECT id, request_hash FROM role_policy_change_requests
                WHERE requested_by_subject_id = :requester AND idempotency_key = :key
                """).param("requester", requester).param("key", idempotencyKey).query(IdempotencyRow.class)
            .optional().orElse(null);
        if (existing != null) {
            if (!existing.requestHash().equals(hash)) {
                throw error("IDEMPOTENCY_CONFLICT", "Idempotency key was used for a different request");
            }
            return findRequest(existing.id());
        }
        var id = jdbc.sql("""
                INSERT INTO role_policy_change_requests(target_role_id, target_role_code,
                    requested_by_subject_id, change_type, requested_payload, request_hash,
                    expected_role_version, reason, idempotency_key)
                VALUES (:roleId, :roleCode, :requester, :changeType, CAST(:payload AS jsonb),
                    :hash, :expectedVersion, :reason, :key)
                RETURNING id
                """).param("roleId", roleId).param("roleCode", roleCode).param("requester", requester)
            .param("changeType", changeType).param("payload", payload).param("hash", hash)
            .param("expectedVersion", expectedVersion).param("reason", reason.trim())
            .param("key", idempotencyKey).query(UUID.class).single();
        return findRequest(id);
    }

    private RoleView view(RoleRow role) {
        var batch = policies.get(role.audience(), List.of(role.code()));
        var policy = batch.policies().stream().findFirst().orElse(
            new RolePolicyService.RolePolicy(role.code(), role.policyVersion(), List.of()));
        var grants = policy.permissions().stream().map(item -> new GrantView(
            item.permissionCode(), item.allowedScopes(), item.partitionTypes())).toList();
        return new RoleView(role.code(), role.displayName(), role.description(), role.audience(),
            role.systemRole(), role.active(), role.policyVersion(), grants,
            role.createdAt().toString(), role.updatedAt().toString());
    }

    private void validatePermissions(List<GrantInput> grants) {
        for (var grant : grants) permissionId(grant.permissionCode());
    }

    private UUID permissionId(String code) {
        return jdbc.sql("SELECT id FROM permissions WHERE code = :code AND active")
            .param("code", code).query(UUID.class).optional()
            .orElseThrow(() -> error("PERMISSION_NOT_FOUND", "Permission is not active: " + code));
    }

    private static List<GrantInput> normalizeGrants(List<GrantInput> values) {
        if (values == null) return List.of();
        var seen = new LinkedHashSet<String>();
        var result = new ArrayList<GrantInput>();
        for (var value : values) {
            if (value == null) throw error("INVALID_ROLE_GRANT", "Role grant is required");
            var code = value.permissionCode() == null ? "" : value.permissionCode().trim();
            if (!PERMISSION_CODE.matcher(code).matches() || !seen.add(code)) {
                throw error("INVALID_ROLE_GRANT", "Permission codes must be unique canonical codes");
            }
            var scopes = value.allowedScopes() == null ? Set.<String>of()
                : value.allowedScopes().stream().map(scope -> scope.trim().toUpperCase())
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
            if (scopes.isEmpty() || !SCOPES.containsAll(scopes)) {
                throw error("INVALID_ROLE_GRANT", "Every permission needs valid allowed scopes");
            }
            var partitions = value.partitionTypes() == null ? Set.<String>of()
                : value.partitionTypes().stream().map(type -> type.trim().toUpperCase())
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
            if (!scopes.contains("PARTITION") && !partitions.isEmpty()) {
                throw error("INVALID_ROLE_GRANT", "Partition types require PARTITION scope");
            }
            if (partitions.stream().anyMatch(type -> !type.matches("^[A-Z][A-Z0-9_]{1,63}$"))) {
                throw error("INVALID_ROLE_GRANT", "Invalid partition type");
            }
            result.add(new GrantInput(code, List.copyOf(scopes), List.copyOf(partitions)));
        }
        result.sort(Comparator.comparing(GrantInput::permissionCode));
        return List.copyOf(result);
    }

    private static List<String> normalizePermissionCodes(List<String> values) {
        if (values == null) return List.of();
        var result = new LinkedHashSet<String>();
        for (var value : values) {
            var code = value == null ? "" : value.trim();
            if (!PERMISSION_CODE.matcher(code).matches()) {
                throw error("INVALID_PERMISSION_CODE", "Invalid canonical permission code");
            }
            result.add(code);
        }
        return result.stream().sorted().toList();
    }

    private void protectRescuePolicy(
        RoleRow role,
        List<String> removals,
        List<GrantInput> additions
    ) {
        if (!Set.of("SUPER_ADMIN", "SECURITY_ADMIN").contains(role.code())) return;
        var removesRescue = removals.stream().anyMatch(RESCUE_PERMISSIONS::contains);
        var weakensRescue = additions.stream().anyMatch(grant ->
            RESCUE_PERMISSIONS.contains(grant.permissionCode())
                && !grant.allowedScopes().contains("ALL"));
        if (removesRescue || weakensRescue) {
            throw error("PROTECTED_ROLE_INVARIANT", "Protected roles must retain the ALL-scoped rescue policy");
        }
    }

    private RoleRow findRole(String accountType, String roleCode, boolean lock) {
        return jdbc.sql("""
                SELECT id, code, display_name, description, audience, system_role, active,
                       policy_version, created_at, updated_at
                FROM roles WHERE audience = :audience AND code = :code
                """ + (lock ? " FOR UPDATE" : ""))
            .param("audience", accountType).param("code", roleCode).query(RoleRow.class).optional()
            .orElseThrow(() -> error("ROLE_NOT_FOUND", "Role was not found"));
    }

    private RoleRow lockRole(UUID id) {
        return jdbc.sql("""
                SELECT id, code, display_name, description, audience, system_role, active,
                       policy_version, created_at, updated_at
                FROM roles WHERE id = :id FOR UPDATE
                """).param("id", id).query(RoleRow.class).optional()
            .orElseThrow(() -> error("ROLE_NOT_FOUND", "Role was not found"));
    }

    private RoleRow bumpRoleVersion(UUID roleId) {
        return jdbc.sql("""
                UPDATE roles SET policy_version = policy_version + 1, updated_at = now()
                WHERE id = :id
                RETURNING id, code, display_name, description, audience, system_role, active,
                          policy_version, created_at, updated_at
                """).param("id", roleId).query(RoleRow.class).single();
    }

    private static void requireVersion(RoleRow role, Long expected) {
        if (expected == null || role.policyVersion() != expected) {
            throw error("ROLE_VERSION_CONFLICT", "Role policy version is stale");
        }
    }

    private RequestRow lockRequest(UUID id) {
        expirePending();
        return jdbc.sql("""
                SELECT id, target_role_id, target_role_code, requested_by_subject_id,
                       change_type, status, requested_payload::text AS payload,
                       expected_role_version, expires_at
                FROM role_policy_change_requests WHERE id = :id FOR UPDATE
                """).param("id", id).query(RequestRow.class).optional()
            .orElseThrow(() -> error("ROLE_POLICY_CHANGE_NOT_FOUND", "Role-policy change was not found"));
    }

    private void requirePending(RequestRow request) {
        if (!"PENDING".equals(request.status())) {
            throw error("ROLE_POLICY_CHANGE_NOT_PENDING", "Role-policy change is not pending");
        }
    }

    private void expirePending() {
        jdbc.sql("""
                UPDATE role_policy_change_requests SET status = 'EXPIRED'
                WHERE status = 'PENDING' AND expires_at <= now()
                """).update();
    }

    private void markStale(UUID id, UUID reviewer, String reason) {
        jdbc.sql("""
                UPDATE role_policy_change_requests SET status = 'STALE',
                    reviewed_by_subject_id = :reviewer, review_reason = :reason, reviewed_at = now()
                WHERE id = :id
                """).param("reviewer", reviewer).param("reason", reason.trim()).param("id", id).update();
    }

    private long bumpCatalogVersion() {
        return jdbc.sql("""
                UPDATE authorization_catalog_state
                SET catalog_version = catalog_version + 1, updated_at = now()
                WHERE singleton RETURNING catalog_version
                """).query(Long.class).single();
    }

    private void emitPolicyChanged(RoleRow role, long catalogVersion) {
        var payload = write(Map.of(
            "accountType", role.audience(), "roleCode", role.code(),
            "roleVersion", role.policyVersion(), "catalogVersion", catalogVersion,
            "changedAt", OffsetDateTime.now(ZoneOffset.UTC).toString()));
        jdbc.sql("""
                INSERT INTO outbox_events(aggregate_type, aggregate_id, aggregate_version,
                    event_type, event_version, payload)
                VALUES ('Role', :roleId, :version, :eventType, 1, CAST(:payload AS jsonb))
                """).param("roleId", role.id()).param("version", role.policyVersion())
            .param("eventType", ROLE_POLICY_CHANGED).param("payload", payload).update();
    }

    /**
     * Dual-read bridge for services not yet moved to role-policy v2. This is a
     * projection of the role policy, never a separately editable user policy.
     */
    private void reconcileCompatibilityAssignments(RoleRow role) {
        var subjects = jdbc.sql("""
                SELECT DISTINCT subject.id, subject.account_type, subject.auth_account_id,
                       subject.active, subject.authorization_version
                FROM subject_role_assignments assignment
                JOIN authorization_subjects subject ON subject.id = assignment.subject_id
                WHERE assignment.role_id = :roleId AND assignment.revoked_at IS NULL
                  AND assignment.valid_from <= now()
                  AND (assignment.valid_until IS NULL OR assignment.valid_until > now())
                ORDER BY subject.id
                """).param("roleId", role.id()).query(CompatibilitySubjectRow.class).list();
        if (subjects.isEmpty()) return;

        jdbc.sql("""
                DELETE FROM subject_role_permission_scopes scope
                USING subject_role_assignments assignment
                WHERE scope.assignment_id = assignment.id AND assignment.role_id = :roleId
                  AND assignment.revoked_at IS NULL
                  AND assignment.valid_from <= now()
                  AND (assignment.valid_until IS NULL OR assignment.valid_until > now())
                """).param("roleId", role.id()).update();
        if (role.active()) {
            jdbc.sql("""
                    INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
                    SELECT assignment.id, policy.permission_id, policy.scope_type
                    FROM subject_role_assignments assignment
                    JOIN role_permission_policies policy ON policy.role_id = assignment.role_id
                    JOIN permissions permission ON permission.id = policy.permission_id AND permission.active
                    WHERE assignment.role_id = :roleId AND assignment.revoked_at IS NULL
                      AND assignment.valid_from <= now()
                      AND (assignment.valid_until IS NULL OR assignment.valid_until > now())
                    ON CONFLICT DO NOTHING
                    """).param("roleId", role.id()).update();
        }

        for (var subject : subjects) {
            var version = jdbc.sql("""
                    UPDATE authorization_subjects
                    SET authorization_version = authorization_version + 1, updated_at = now()
                    WHERE id = :id RETURNING authorization_version
                    """).param("id", subject.id()).query(Long.class).single();
            emitAuthorizationChanged(subject, version);
        }
    }

    private void emitAuthorizationChanged(CompatibilitySubjectRow subject, long version) {
        var payload = write(Map.of(
            "accountId", subject.authAccountId().toString(),
            "accountType", subject.accountType(),
            "authorizationVersion", version,
            "changedAt", OffsetDateTime.now(ZoneOffset.UTC).toString()));
        jdbc.sql("""
                INSERT INTO outbox_events(aggregate_type, aggregate_id, aggregate_version,
                    event_type, event_version, payload)
                VALUES ('AuthorizationSubject', :subjectId, :version,
                    'vistay.user.authorization-changed', 1, CAST(:payload AS jsonb))
                """).param("subjectId", subject.id()).param("version", version)
            .param("payload", payload).update();
    }

    private void audit(UUID actor, String action, RoleRow role, String reason) {
        jdbc.sql("""
                INSERT INTO authorization_audit_events(actor_subject_id, action, after_state, reason)
                VALUES (:actor, :action, CAST(:after AS jsonb), :reason)
                """).param("actor", actor).param("action", action)
            .param("after", write(Map.of("roleCode", role.code(), "roleVersion", role.policyVersion(),
                "active", role.active()))).param("reason", reason.trim()).update();
    }

    private void evictAfterCommit(String accountType, String roleCode) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            policies.evict(accountType, roleCode);
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() { policies.evict(accountType, roleCode); }
        });
    }

    private ChangeRequestView findRequest(UUID id) {
        return jdbc.sql("""
                SELECT id, target_role_code, requested_by_subject_id, reviewed_by_subject_id,
                       change_type, status, expected_role_version, reason, review_reason,
                       expires_at, created_at
                FROM role_policy_change_requests WHERE id = :id
                """).param("id", id).query(ChangeRequestRow.class).single().view();
    }

    private static String normalizeRoleCode(String value) {
        var code = value == null ? "" : value.trim().toUpperCase();
        if (!ROLE_CODE.matcher(code).matches()) throw error("INVALID_ROLE_CODE", "Invalid role code");
        return code;
    }

    private static String normalizeAccountType(String value) {
        var type = value == null ? "" : value.trim().toUpperCase();
        if (!ACCOUNT_TYPES.contains(type)) throw error("INVALID_ACCOUNT_TYPE", "Unsupported account type");
        return type;
    }

    private static void requireDisplayName(String value) {
        if (value == null || value.trim().length() < 3 || value.trim().length() > 120) {
            throw error("INVALID_ROLE_NAME", "Role display name must contain 3-120 characters");
        }
    }

    private static void requireReason(String value) {
        if (value == null || value.trim().length() < 8) {
            throw error("INVALID_REASON", "Reason must contain at least 8 characters");
        }
    }

    private static void requireIdempotencyKey(String value) {
        if (value == null || value.isBlank() || value.length() > 160) {
            throw error("INVALID_IDEMPOTENCY_KEY", "Idempotency key is required and limited to 160 characters");
        }
    }

    private String write(Object value) {
        try { return json.writeValueAsString(value); }
        catch (RuntimeException invalid) { throw new IllegalStateException("Cannot serialize role policy", invalid); }
    }

    private tools.jackson.databind.JsonNode read(String value) {
        try { return json.readTree(value); }
        catch (RuntimeException invalid) { throw error("INVALID_ROLE_POLICY_PAYLOAD", "Stored role-policy payload is invalid"); }
    }

    private List<GrantInput> parseGrants(tools.jackson.databind.JsonNode node) {
        var values = new ArrayList<GrantInput>();
        node.forEach(item -> {
            var scopes = new ArrayList<String>();
            item.get("allowedScopes").forEach(scope -> scopes.add(scope.asString()));
            var partitions = new ArrayList<String>();
            item.get("partitionTypes").forEach(type -> partitions.add(type.asString()));
            values.add(new GrantInput(item.get("permissionCode").asString(), scopes, partitions));
        });
        return normalizeGrants(values);
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static GraphqlErrorException error(String code, String message) {
        var classification = Set.of("FORBIDDEN_PERMISSION", "MAKER_CHECKER_VIOLATION",
            "SYSTEM_ROLE_PROTECTED", "PROTECTED_ROLE_INVARIANT").contains(code)
            ? ErrorType.FORBIDDEN : code.endsWith("NOT_FOUND") ? ErrorType.NOT_FOUND : ErrorType.BAD_REQUEST;
        return GraphqlErrorException.newErrorException().message(message)
            .errorClassification(classification).extensions(Map.of("code", code)).build();
    }

    private record RoleRow(UUID id, String code, String displayName, String description,
        String audience, boolean systemRole, boolean active, long policyVersion,
        OffsetDateTime createdAt, OffsetDateTime updatedAt) {}
    private record PermissionRow(UUID id, String code, String resource, String action,
        String description, boolean active, OffsetDateTime deprecatedAt) {}
    private record CompatibilitySubjectRow(UUID id, String accountType, UUID authAccountId,
        boolean active, long authorizationVersion) {}
    private record RequestRow(UUID id, UUID targetRoleId, String targetRoleCode,
        UUID requestedBySubjectId, String changeType, String status, String payload,
        Long expectedRoleVersion, OffsetDateTime expiresAt) {}
    private record IdempotencyRow(UUID id, String requestHash) {}
    private record ChangeRequestRow(UUID id, String targetRoleCode, UUID requestedBySubjectId,
        UUID reviewedBySubjectId, String changeType, String status, Long expectedRoleVersion,
        String reason, String reviewReason, OffsetDateTime expiresAt, OffsetDateTime createdAt) {
        private ChangeRequestView view() {
            return new ChangeRequestView(id, targetRoleCode, requestedBySubjectId, reviewedBySubjectId,
                changeType, status, expectedRoleVersion, reason, reviewReason,
                expiresAt.toString(), createdAt.toString());
        }
    }

    public record GrantInput(String permissionCode, List<String> allowedScopes, List<String> partitionTypes) {}
    public record CreateRoleInput(String code, String displayName, String description, String accountType,
        List<GrantInput> grants, String reason, String idempotencyKey) {}
    public record PermissionChangeInput(String roleCode, String accountType, List<GrantInput> addGrants,
        List<String> removePermissionCodes, long expectedRoleVersion, String reason, String idempotencyKey) {}
    public record DeactivateRoleInput(String roleCode, String accountType, long expectedRoleVersion,
        String reason, String idempotencyKey) {}
    public record GrantView(String permissionCode, List<String> allowedScopes, List<String> partitionTypes) {}
    public record RoleView(String code, String displayName, String description, String accountType,
        boolean systemRole, boolean active, long roleVersion, List<GrantView> grants,
        String createdAt, String updatedAt) {}
    public record PermissionView(String code, String resource, String action, String description,
        boolean active, String deprecatedAt, List<String> aliases) {}
    public record ChangeRequestView(UUID id, String roleCode, UUID requestedBySubjectId,
        UUID reviewedBySubjectId, String changeType, String status, Long expectedRoleVersion,
        String reason, String reviewReason, String expiresAt, String createdAt) {}
}
