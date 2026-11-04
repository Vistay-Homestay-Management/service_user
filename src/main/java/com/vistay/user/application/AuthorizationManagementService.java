package com.vistay.user.application;

import com.vistay.user.application.AuthorizationSnapshotService.Scope;
import graphql.GraphqlErrorException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

@Service
public class AuthorizationManagementService {
    public static final String AUTHORIZATION_CHANGED = "vistay.user.authorization-changed";

    private final JdbcClient jdbc;
    private final ObjectMapper json;
    private final AuthorizationSnapshotService snapshots;

    public AuthorizationManagementService(
        JdbcClient jdbc,
        ObjectMapper json,
        AuthorizationSnapshotService snapshots
    ) {
        this.jdbc = jdbc;
        this.json = json;
        this.snapshots = snapshots;
    }

    public Actor requireActor(UUID accountId, String permission) {
        var snapshot = snapshots.get("ADMIN", accountId);
        if (!snapshot.active() || snapshot.subjectId() == null) {
            throw error("UNAUTHENTICATED", "The administrator profile is not active");
        }
        if (!snapshot.allows(permission, Scope.ALL)) {
            throw error("FORBIDDEN_PERMISSION", "Missing permission " + permission + "@ALL");
        }
        return new Actor(snapshot.subjectId(), snapshot.profileId(), snapshot.authorizationVersion());
    }

    public List<RoleView> catalog(UUID actorAccountId, String accountType) {
        requireActor(actorAccountId, "authorization:read");
        var normalizedType = normalizeAccountType(accountType);
        var roles = jdbc.sql("""
                SELECT id, code, display_name, audience
                FROM roles WHERE audience = :accountType AND active
                ORDER BY code
                """)
            .param("accountType", normalizedType)
            .query(RoleRow.class)
            .list();
        return roles.stream().map(role -> new RoleView(role.code(), role.displayName(), role.audience(),
            policies(role.id()))).toList();
    }

    public SubjectView subject(UUID actorAccountId, UUID subjectId) {
        requireActor(actorAccountId, "authorization:read");
        return loadSubject(subjectId);
    }

    public SubjectView subjectByAccount(UUID actorAccountId, String accountType, UUID accountId) {
        requireActor(actorAccountId, "authorization:read");
        var subjectId = jdbc.sql("""
                SELECT id FROM authorization_subjects
                WHERE account_type = :accountType AND auth_account_id = :accountId
                """).param("accountType", normalizeAccountType(accountType)).param("accountId", accountId)
            .query(UUID.class).optional()
            .orElseThrow(() -> error("AUTHORIZATION_SUBJECT_NOT_FOUND", "Authorization subject was not found"));
        return loadSubject(subjectId);
    }

    public List<ChangeRequestView> changeRequests(UUID actorAccountId, String status) {
        requireActor(actorAccountId, "authorization:read");
        expirePending();
        return jdbc.sql("""
                SELECT id, target_subject_id, requested_by_subject_id, reviewed_by_subject_id,
                       change_type, status, requested_payload ->> 'roleCode' AS role_code,
                       reason, review_reason, expires_at, created_at
                FROM authorization_change_requests
                WHERE status = :status ORDER BY created_at DESC LIMIT 200
                """)
            .param("status", status)
            .query(ChangeRequestView.class)
            .list();
    }

    public List<AuditView> audit(UUID actorAccountId, UUID targetSubjectId) {
        requireActor(actorAccountId, "audit:read");
        var sql = targetSubjectId == null
            ? """
                SELECT id, actor_subject_id, target_subject_id, action, reason, correlation_id, created_at
                FROM authorization_audit_events ORDER BY created_at DESC LIMIT 200
                """
            : """
                SELECT id, actor_subject_id, target_subject_id, action, reason, correlation_id, created_at
                FROM authorization_audit_events WHERE target_subject_id = :targetId
                ORDER BY created_at DESC LIMIT 200
                """;
        var query = jdbc.sql(sql);
        if (targetSubjectId != null) {
            query = query.param("targetId", targetSubjectId);
        }
        return query.query(AuditView.class).list();
    }

    @Transactional
    public ChangeRequestView requestChange(UUID actorAccountId, ChangeInput input) {
        var actor = requireActor(actorAccountId, "authorization:grant");
        requireReason(input.reason());
        requireIdempotencyKey(input.idempotencyKey());
        var target = lockSubject(input.targetSubjectId());
        requireVersion(target, input.expectedAuthorizationVersion());
        var role = role(input.roleCode(), target.accountType());
        var desired = desiredScopes(role.id(), input.scopeOverrides());
        var existing = activeAssignment(target.id(), role.id());
        var changeType = existing == null ? "GRANT_ROLE" : "EXPAND_SCOPES";
        if (existing != null) {
            ensureExpansion(existing.id(), desired);
        }

        var payload = writeJson(Map.of(
            "roleCode", role.code(),
            "validUntil", input.validUntil() == null ? "" : input.validUntil(),
            "grants", desired.entrySet().stream().map(entry -> Map.of(
                "permissionCode", entry.getKey(),
                "scopes", entry.getValue().stream().map(Enum::name).toList()
            )).toList()
        ));
        var existingRequest = jdbc.sql("""
                SELECT id, target_subject_id, requested_by_subject_id, reviewed_by_subject_id,
                       change_type, status, requested_payload ->> 'roleCode' AS role_code,
                       reason, review_reason, expires_at, created_at,
                       requested_payload::text AS payload
                FROM authorization_change_requests
                WHERE requested_by_subject_id = :actorId AND idempotency_key = :key
                """)
            .param("actorId", actor.subjectId())
            .param("key", input.idempotencyKey().trim())
            .query(IdempotentChangeRow.class)
            .optional();
        if (existingRequest.isPresent()) {
            if (!sameJson(existingRequest.get().payload(), payload)) {
                throw error("IDEMPOTENCY_CONFLICT", "Idempotency key was used with different input");
            }
            return existingRequest.get().view();
        }

        var id = UUID.randomUUID();
        jdbc.sql("""
                INSERT INTO authorization_change_requests(
                    id, target_subject_id, requested_by_subject_id, change_type,
                    requested_payload, reason, expected_authorization_version, idempotency_key
                ) VALUES (:id, :targetId, :actorId, :changeType, CAST(:payload AS jsonb),
                          :reason, :version, :key)
                """)
            .param("id", id)
            .param("targetId", target.id())
            .param("actorId", actor.subjectId())
            .param("changeType", changeType)
            .param("payload", payload)
            .param("reason", input.reason().trim())
            .param("version", target.authorizationVersion())
            .param("key", input.idempotencyKey().trim())
            .update();
        audit(actor.subjectId(), target.id(), "AUTHORIZATION_CHANGE_REQUESTED", Map.of(),
            Map.of("requestId", id, "changeType", changeType, "roleCode", role.code()), input.reason());
        return findChange(id);
    }

    @Transactional
    public ChangeRequestView approve(UUID actorAccountId, UUID requestId, String reason, long expectedVersion) {
        var actor = requireActor(actorAccountId, "authorization:approve");
        requireReason(reason);
        var request = lockChange(requestId);
        requirePending(request);
        if (actor.subjectId().equals(request.requestedBySubjectId())
            || actor.subjectId().equals(request.targetSubjectId())) {
            throw error("MAKER_CHECKER_VIOLATION", "Checker must differ from maker and target");
        }
        var target = lockSubject(request.targetSubjectId());
        requireVersion(target, expectedVersion);
        if (target.authorizationVersion() != request.expectedAuthorizationVersion()) {
            markStale(request.id(), actor.subjectId(), "Target authorization changed after request creation");
            return findChange(request.id());
        }
        var payload = readPayload(request.payload());
        var role = role(payload.roleCode(), target.accountType());
        validateRequestedScopes(role.id(), payload.grants());
        var assignment = activeAssignment(target.id(), role.id());
        var assignmentId = assignment == null
            ? createAssignment(target.id(), role.id(), actor.subjectId(), payload.validUntil())
            : assignment.id();
        for (var grant : payload.grants().entrySet()) {
            var permissionId = permissionId(grant.getKey());
            for (var scope : grant.getValue()) {
                jdbc.sql("""
                        INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
                        VALUES (:assignmentId, :permissionId, :scope) ON CONFLICT DO NOTHING
                        """)
                    .param("assignmentId", assignmentId)
                    .param("permissionId", permissionId)
                    .param("scope", scope.name())
                    .update();
            }
        }
        var newVersion = bumpVersion(target.id());
        jdbc.sql("""
                UPDATE authorization_change_requests SET status = 'APPROVED',
                    reviewed_by_subject_id = :actorId, review_reason = :reason, reviewed_at = now()
                WHERE id = :id
                """)
            .param("actorId", actor.subjectId()).param("reason", reason.trim()).param("id", request.id()).update();
        audit(actor.subjectId(), target.id(), "AUTHORIZATION_CHANGE_APPROVED", Map.of(),
            Map.of("requestId", request.id(), "authorizationVersion", newVersion), reason);
        emitChanged(target, newVersion);
        snapshots.evict(target.accountType(), target.authAccountId());
        return findChange(request.id());
    }

    @Transactional
    public ChangeRequestView reject(UUID actorAccountId, UUID requestId, String reason) {
        var actor = requireActor(actorAccountId, "authorization:approve");
        requireReason(reason);
        var request = lockChange(requestId);
        requirePending(request);
        if (actor.subjectId().equals(request.requestedBySubjectId())
            || actor.subjectId().equals(request.targetSubjectId())) {
            throw error("MAKER_CHECKER_VIOLATION", "Checker must differ from maker and target");
        }
        jdbc.sql("""
                UPDATE authorization_change_requests SET status = 'REJECTED',
                    reviewed_by_subject_id = :actorId, review_reason = :reason, reviewed_at = now()
                WHERE id = :id
                """)
            .param("actorId", actor.subjectId()).param("reason", reason.trim()).param("id", request.id()).update();
        audit(actor.subjectId(), request.targetSubjectId(), "AUTHORIZATION_CHANGE_REJECTED", Map.of(),
            Map.of("requestId", request.id()), reason);
        return findChange(request.id());
    }

    @Transactional
    public SubjectView revoke(UUID actorAccountId, UUID assignmentId, String reason, long expectedVersion) {
        var actor = requireActor(actorAccountId, "authorization:revoke");
        requireReason(reason);
        var assignment = lockAssignment(assignmentId);
        var target = lockSubject(assignment.subjectId());
        requireVersion(target, expectedVersion);
        protectLastApprover(assignment.roleCode(), target.id());
        jdbc.sql("""
                UPDATE subject_role_assignments SET revoked_at = now(), revoke_reason = :reason
                WHERE id = :id AND revoked_at IS NULL
                """)
            .param("reason", reason.trim()).param("id", assignmentId).update();
        var newVersion = bumpVersion(target.id());
        audit(actor.subjectId(), target.id(), "ROLE_REVOKED", Map.of("roleCode", assignment.roleCode()),
            Map.of("authorizationVersion", newVersion), reason);
        emitChanged(target, newVersion);
        snapshots.evict(target.accountType(), target.authAccountId());
        return loadSubject(target.id());
    }

    @Transactional
    public SubjectView reduce(UUID actorAccountId, ReductionInput input) {
        var actor = requireActor(actorAccountId, "authorization:revoke");
        requireReason(input.reason());
        var assignment = lockAssignment(input.assignmentId());
        var target = lockSubject(assignment.subjectId());
        requireVersion(target, input.expectedAuthorizationVersion());
        var retained = normalizeRetained(input.retainedScopes());
        var current = assignmentScopes(assignment.id());
        retained.forEach((permission, scopes) -> {
            if (!current.containsKey(permission) || !current.get(permission).containsAll(scopes)) {
                throw error("INVALID_SCOPE_REDUCTION", "Scope reduction cannot add permission or scope");
            }
        });
        if (retained.equals(current)) {
            throw error("NO_AUTHORIZATION_CHANGE", "No scope would be removed");
        }
        jdbc.sql("DELETE FROM subject_role_permission_scopes WHERE assignment_id = :id")
            .param("id", assignment.id()).update();
        retained.forEach((permission, scopes) -> {
            var permissionId = permissionId(permission);
            scopes.forEach(scope -> jdbc.sql("""
                    INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
                    VALUES (:assignmentId, :permissionId, :scope)
                    """)
                .param("assignmentId", assignment.id()).param("permissionId", permissionId)
                .param("scope", scope.name()).update());
        });
        var newVersion = bumpVersion(target.id());
        audit(actor.subjectId(), target.id(), "AUTHORIZATION_SCOPES_REDUCED", current, retained, input.reason());
        emitChanged(target, newVersion);
        snapshots.evict(target.accountType(), target.authAccountId());
        return loadSubject(target.id());
    }

    @Transactional
    public SubjectView establishSecondApprover(UUID actorAccountId, UUID targetSubjectId, String reason) {
        var actor = requireActor(actorAccountId, "authorization:approve");
        requireReason(reason);
        var state = jdbc.sql("""
                SELECT first_super_admin_subject_id, second_approver_subject_id, exception_consumed_at
                FROM authorization_bootstrap_state WHERE singleton FOR UPDATE
                """).query(BootstrapState.class).single();
        if (state.exceptionConsumedAt() != null) {
            throw error("BOOTSTRAP_EXCEPTION_CONSUMED", "The bootstrap quorum exception was already used");
        }
        if (!actor.subjectId().equals(state.firstSuperAdminSubjectId())) {
            throw error("FORBIDDEN_BOOTSTRAP_ACTOR", "Only the first SuperAdmin may establish the second approver");
        }
        if (actor.subjectId().equals(targetSubjectId)) {
            throw error("MAKER_CHECKER_VIOLATION", "Second approver must be a different administrator");
        }
        var target = lockSubject(targetSubjectId);
        if (!"ADMIN".equals(target.accountType()) || !target.active()) {
            throw error("INVALID_BOOTSTRAP_TARGET", "Second approver must be an active administrator");
        }
        var role = role("SECURITY_ADMIN", "ADMIN");
        if (activeAssignment(target.id(), role.id()) != null) {
            throw error("ROLE_ALREADY_ASSIGNED", "Target already has SECURITY_ADMIN");
        }
        var assignmentId = createAssignment(target.id(), role.id(), actor.subjectId(), null);
        for (var policy : policies(role.id())) {
            var permissionId = permissionId(policy.permissionCode());
            for (var scope : policy.defaultScopes()) {
                jdbc.sql("""
                        INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
                        VALUES (:assignmentId, :permissionId, :scope)
                        """)
                    .param("assignmentId", assignmentId).param("permissionId", permissionId)
                    .param("scope", scope.name()).update();
            }
        }
        jdbc.sql("""
                UPDATE authorization_bootstrap_state SET second_approver_subject_id = :targetId,
                    exception_consumed_at = now() WHERE singleton
                """).param("targetId", target.id()).update();
        var newVersion = bumpVersion(target.id());
        audit(actor.subjectId(), target.id(), "BOOTSTRAP_QUORUM_ESTABLISHED", Map.of(),
            Map.of("roleCode", "SECURITY_ADMIN", "authorizationVersion", newVersion), reason);
        emitChanged(target, newVersion);
        snapshots.evict(target.accountType(), target.authAccountId());
        return loadSubject(target.id());
    }

    private List<PermissionPolicyView> policies(UUID roleId) {
        var rows = jdbc.sql("""
                SELECT p.code AS permission_code, rpp.scope_type, rpp.default_scope
                FROM role_permission_policies rpp JOIN permissions p ON p.id = rpp.permission_id
                WHERE rpp.role_id = :roleId AND p.active ORDER BY p.code, rpp.scope_type
                """).param("roleId", roleId).query(PolicyRow.class).list();
        Map<String, List<PolicyRow>> grouped = new LinkedHashMap<>();
        rows.forEach(row -> grouped.computeIfAbsent(row.permissionCode(), ignored -> new ArrayList<>()).add(row));
        return grouped.entrySet().stream().map(entry -> new PermissionPolicyView(entry.getKey(),
            entry.getValue().stream().map(row -> Scope.valueOf(row.scopeType())).distinct().toList(),
            entry.getValue().stream().filter(PolicyRow::defaultScope)
                .map(row -> Scope.valueOf(row.scopeType())).distinct().toList())).toList();
    }

    private SubjectView loadSubject(UUID subjectId) {
        var target = subjectRow(subjectId, false);
        var assignments = jdbc.sql("""
                SELECT sra.id, r.code AS role_code, sra.valid_until
                FROM subject_role_assignments sra JOIN roles r ON r.id = sra.role_id
                WHERE sra.subject_id = :subjectId AND sra.revoked_at IS NULL
                  AND sra.valid_from <= now() AND (sra.valid_until IS NULL OR sra.valid_until > now())
                ORDER BY r.code
                """).param("subjectId", subjectId).query(AssignmentViewRow.class).list().stream()
            .map(row -> new AssignmentView(row.id(), row.roleCode(),
                row.validUntil() == null ? null : row.validUntil().toString(), grantViews(assignmentScopes(row.id()))))
            .toList();
        Map<String, Set<Scope>> effective = new LinkedHashMap<>();
        assignments.forEach(assignment -> assignment.grants().forEach(grant ->
            effective.computeIfAbsent(grant.permissionCode(), ignored -> new LinkedHashSet<>())
                .addAll(grant.scopes())));
        return new SubjectView(target.id(), target.accountType(), target.authAccountId(), profileId(target),
            target.active(), target.authorizationVersion(), assignments, grantViews(effective));
    }

    private UUID profileId(SubjectRow target) {
        var table = switch (target.accountType()) {
            case "ADMIN" -> "admin_users";
            case "CUSTOMER" -> "customers";
            case "HOST" -> "hosts";
            default -> throw error("INVALID_ACCOUNT_TYPE", "Unsupported account type");
        };
        return jdbc.sql("SELECT id FROM " + table + " WHERE authorization_subject_id = :subjectId")
            .param("subjectId", target.id()).query(UUID.class).single();
    }

    private Map<String, Set<Scope>> desiredScopes(UUID roleId, List<ScopeOverride> overrides) {
        var policyList = policies(roleId);
        Map<String, Set<Scope>> desired = new LinkedHashMap<>();
        Map<String, PermissionPolicyView> policiesByCode = new HashMap<>();
        policyList.forEach(policy -> {
            policiesByCode.put(policy.permissionCode(), policy);
            desired.put(policy.permissionCode(), new LinkedHashSet<>(policy.defaultScopes()));
        });
        if (overrides != null) {
            for (var override : overrides) {
                var policy = policiesByCode.get(override.permissionCode());
                if (policy == null || override.scopes() == null || override.scopes().isEmpty()
                    || !new LinkedHashSet<>(policy.allowedScopes()).containsAll(override.scopes())) {
                    throw error("INVALID_SCOPE_POLICY", "Scope is not allowed for " + override.permissionCode());
                }
                desired.put(override.permissionCode(), new LinkedHashSet<>(override.scopes()));
            }
        }
        if (desired.values().stream().anyMatch(Set::isEmpty)) {
            throw error("INVALID_SCOPE_POLICY", "Every permission must have a data scope");
        }
        return desired;
    }

    private void validateRequestedScopes(UUID roleId, Map<String, Set<Scope>> requested) {
        var allowed = new HashMap<String, Set<Scope>>();
        policies(roleId).forEach(policy -> allowed.put(policy.permissionCode(), new LinkedHashSet<>(policy.allowedScopes())));
        requested.forEach((permission, scopes) -> {
            if (!allowed.containsKey(permission) || scopes.isEmpty() || !allowed.get(permission).containsAll(scopes)) {
                throw error("INVALID_SCOPE_POLICY", "Requested scope no longer matches the role policy");
            }
        });
    }

    private void ensureExpansion(UUID assignmentId, Map<String, Set<Scope>> desired) {
        var current = assignmentScopes(assignmentId);
        var addsSomething = desired.entrySet().stream().anyMatch(entry ->
            !current.getOrDefault(entry.getKey(), Set.of()).containsAll(entry.getValue()));
        if (!addsSomething) {
            throw error("NO_AUTHORIZATION_CHANGE", "Requested grants do not expand current authorization");
        }
    }

    private Map<String, Set<Scope>> assignmentScopes(UUID assignmentId) {
        var rows = jdbc.sql("""
                SELECT p.code AS permission_code, srps.scope_type
                FROM subject_role_permission_scopes srps JOIN permissions p ON p.id = srps.permission_id
                WHERE srps.assignment_id = :assignmentId AND p.active
                ORDER BY p.code, srps.scope_type
                """).param("assignmentId", assignmentId).query(ScopeRow.class).list();
        Map<String, Set<Scope>> result = new LinkedHashMap<>();
        rows.forEach(row -> result.computeIfAbsent(row.permissionCode(), ignored -> new LinkedHashSet<>())
            .add(Scope.valueOf(row.scopeType())));
        return result;
    }

    private Map<String, Set<Scope>> normalizeRetained(List<RetainedScopes> retained) {
        Map<String, Set<Scope>> result = new LinkedHashMap<>();
        if (retained != null) {
            retained.forEach(item -> result.computeIfAbsent(item.permissionCode(), ignored -> new LinkedHashSet<>())
                .addAll(item.scopes() == null ? List.of() : item.scopes()));
        }
        return result;
    }

    private List<GrantView> grantViews(Map<String, ? extends Collection<Scope>> grants) {
        return grants.entrySet().stream().sorted(Map.Entry.comparingByKey())
            .map(entry -> new GrantView(entry.getKey(), entry.getValue().stream()
                .sorted(Comparator.comparing(Enum::name)).toList()))
            .toList();
    }

    private RoleRow role(String code, String accountType) {
        return jdbc.sql("""
                SELECT id, code, display_name, audience FROM roles
                WHERE code = :code AND audience = :accountType AND active
                """).param("code", code).param("accountType", accountType).query(RoleRow.class).optional()
            .orElseThrow(() -> error("ROLE_NOT_FOUND", "Role is not active for target account type"));
    }

    private SubjectRow lockSubject(UUID id) { return subjectRow(id, true); }

    private SubjectRow subjectRow(UUID id, boolean lock) {
        return jdbc.sql("""
                SELECT id, account_type, auth_account_id, active, authorization_version
                FROM authorization_subjects WHERE id = :id
                """ + (lock ? " FOR UPDATE" : ""))
            .param("id", id).query(SubjectRow.class).optional()
            .orElseThrow(() -> error("AUTHORIZATION_SUBJECT_NOT_FOUND", "Authorization subject was not found"));
    }

    private AssignmentRow activeAssignment(UUID subjectId, UUID roleId) {
        return jdbc.sql("""
                SELECT sra.id, sra.subject_id, r.code AS role_code
                FROM subject_role_assignments sra JOIN roles r ON r.id = sra.role_id
                WHERE sra.subject_id = :subjectId AND sra.role_id = :roleId AND sra.revoked_at IS NULL
                """).param("subjectId", subjectId).param("roleId", roleId)
            .query(AssignmentRow.class).optional().orElse(null);
    }

    private AssignmentRow lockAssignment(UUID id) {
        return jdbc.sql("""
                SELECT sra.id, sra.subject_id, r.code AS role_code
                FROM subject_role_assignments sra JOIN roles r ON r.id = sra.role_id
                WHERE sra.id = :id AND sra.revoked_at IS NULL FOR UPDATE
                """).param("id", id).query(AssignmentRow.class).optional()
            .orElseThrow(() -> error("ASSIGNMENT_NOT_FOUND", "Active role assignment was not found"));
    }

    private UUID createAssignment(UUID subjectId, UUID roleId, UUID actorId, String validUntil) {
        OffsetDateTime end = validUntil == null || validUntil.isBlank() ? null : OffsetDateTime.parse(validUntil);
        return jdbc.sql("""
                INSERT INTO subject_role_assignments(subject_id, role_id, assigned_by_subject_id, valid_until)
                VALUES (:subjectId, :roleId, :actorId, :validUntil) RETURNING id
                """).param("subjectId", subjectId).param("roleId", roleId).param("actorId", actorId)
            .param("validUntil", end).query(UUID.class).single();
    }

    private UUID permissionId(String code) {
        return jdbc.sql("SELECT id FROM permissions WHERE code = :code AND active")
            .param("code", code).query(UUID.class).optional()
            .orElseThrow(() -> error("PERMISSION_NOT_FOUND", "Permission is not active: " + code));
    }

    private long bumpVersion(UUID subjectId) {
        return jdbc.sql("""
                UPDATE authorization_subjects SET authorization_version = authorization_version + 1,
                    updated_at = now() WHERE id = :id RETURNING authorization_version
                """).param("id", subjectId).query(Long.class).single();
    }

    private void emitChanged(SubjectRow target, long version) {
        var payload = writeJson(Map.of(
            "accountId", target.authAccountId().toString(),
            "accountType", target.accountType(),
            "authorizationVersion", version,
            "changedAt", OffsetDateTime.now(ZoneOffset.UTC).toString()
        ));
        jdbc.sql("""
                INSERT INTO outbox_events(aggregate_type, aggregate_id, aggregate_version,
                    event_type, event_version, payload)
                VALUES ('AuthorizationSubject', :subjectId, :version, :eventType, 1, CAST(:payload AS jsonb))
                """).param("subjectId", target.id()).param("version", version)
            .param("eventType", AUTHORIZATION_CHANGED).param("payload", payload).update();
    }

    private void audit(UUID actorId, UUID targetId, String action, Object before, Object after, String reason) {
        jdbc.sql("""
                INSERT INTO authorization_audit_events(actor_subject_id, target_subject_id, action,
                    before_state, after_state, reason)
                VALUES (:actorId, :targetId, :action, CAST(:before AS jsonb), CAST(:after AS jsonb), :reason)
                """).param("actorId", actorId).param("targetId", targetId).param("action", action)
            .param("before", writeJson(before)).param("after", writeJson(after)).param("reason", reason.trim()).update();
    }

    private void protectLastApprover(String roleCode, UUID targetSubjectId) {
        if (!Set.of("SUPER_ADMIN", "SECURITY_ADMIN").contains(roleCode)) return;
        var approvers = jdbc.sql("""
                SELECT count(DISTINCT sra.subject_id)
                FROM subject_role_assignments sra
                JOIN subject_role_permission_scopes srps ON srps.assignment_id = sra.id
                JOIN permissions p ON p.id = srps.permission_id
                JOIN authorization_subjects s ON s.id = sra.subject_id AND s.active
                WHERE sra.revoked_at IS NULL AND p.code = 'authorization:approve' AND srps.scope_type = 'ALL'
                """).query(Long.class).single();
        if (approvers <= 1) {
            throw error("LAST_APPROVER_PROTECTED", "The last authorization approver cannot be revoked");
        }
    }

    private void expirePending() {
        jdbc.sql("""
                UPDATE authorization_change_requests SET status = 'EXPIRED'
                WHERE status = 'PENDING' AND expires_at <= now()
                """).update();
    }

    private ChangeRequestRow lockChange(UUID id) {
        expirePending();
        return jdbc.sql("""
                SELECT id, target_subject_id, requested_by_subject_id, change_type, status,
                       requested_payload::text AS payload, expected_authorization_version, expires_at
                FROM authorization_change_requests WHERE id = :id FOR UPDATE
                """).param("id", id).query(ChangeRequestRow.class).optional()
            .orElseThrow(() -> error("AUTHORIZATION_CHANGE_NOT_FOUND", "Authorization change was not found"));
    }

    private ChangeRequestView findChange(UUID id) {
        return jdbc.sql("""
                SELECT id, target_subject_id, requested_by_subject_id, reviewed_by_subject_id,
                       change_type, status, requested_payload ->> 'roleCode' AS role_code,
                       reason, review_reason, expires_at, created_at
                FROM authorization_change_requests WHERE id = :id
                """).param("id", id).query(ChangeRequestView.class).single();
    }

    private void requirePending(ChangeRequestRow request) {
        if (!"PENDING".equals(request.status())) {
            throw error("AUTHORIZATION_CHANGE_NOT_PENDING", "Authorization change is " + request.status());
        }
    }

    private void markStale(UUID requestId, UUID actorId, String reason) {
        jdbc.sql("""
                UPDATE authorization_change_requests SET status = 'STALE', reviewed_by_subject_id = :actorId,
                    review_reason = :reason, reviewed_at = now() WHERE id = :id
                """).param("actorId", actorId).param("reason", reason).param("id", requestId).update();
    }

    private void requireVersion(SubjectRow subject, long expected) {
        if (subject.authorizationVersion() != expected) {
            throw error("VERSION_CONFLICT", "Expected authorization version " + expected
                + " but found " + subject.authorizationVersion());
        }
    }

    private Payload readPayload(String value) {
        try {
            var root = json.readTree(value);
            var grants = new LinkedHashMap<String, Set<Scope>>();
            root.get("grants").forEach(node -> {
                var scopes = new LinkedHashSet<Scope>();
                node.get("scopes").forEach(scope -> scopes.add(Scope.valueOf(scope.asString())));
                grants.put(node.get("permissionCode").asString(), scopes);
            });
            var validUntil = root.get("validUntil").asString();
            return new Payload(root.get("roleCode").asString(), validUntil.isBlank() ? null : validUntil, grants);
        } catch (RuntimeException invalid) {
            throw error("INVALID_AUTHORIZATION_PAYLOAD", "Stored authorization request is invalid");
        }
    }

    private String writeJson(Object value) {
        try { return json.writeValueAsString(value); }
        catch (RuntimeException failure) { throw new IllegalStateException("Cannot serialize authorization data", failure); }
    }

    private boolean sameJson(String left, String right) {
        try {
            return json.readTree(left).equals(json.readTree(right));
        } catch (Exception invalid) {
            throw error("INVALID_AUTHORIZATION_PAYLOAD", "Stored authorization request is invalid");
        }
    }

    private static String normalizeAccountType(String value) {
        var normalized = value == null ? "" : value.trim().toUpperCase();
        if (!Set.of("CUSTOMER", "ADMIN", "HOST").contains(normalized)) {
            throw error("INVALID_ACCOUNT_TYPE", "Unsupported account type");
        }
        return normalized;
    }

    private static void requireReason(String reason) {
        if (reason == null || reason.trim().length() < 8) {
            throw error("INVALID_REASON", "Reason must contain at least 8 characters");
        }
    }

    private static void requireIdempotencyKey(String key) {
        if (key == null || key.isBlank() || key.length() > 160) {
            throw error("INVALID_IDEMPOTENCY_KEY", "Idempotency key is required and limited to 160 characters");
        }
    }

    private static GraphqlErrorException error(String code, String message) {
        var classification = Set.of("FORBIDDEN_PERMISSION", "MAKER_CHECKER_VIOLATION", "LAST_APPROVER_GUARD")
            .contains(code) ? ErrorType.FORBIDDEN
            : code.endsWith("_NOT_FOUND") ? ErrorType.NOT_FOUND : ErrorType.BAD_REQUEST;
        return GraphqlErrorException.newErrorException().message(message)
            .errorClassification(classification).extensions(Map.of("code", code)).build();
    }

    private record RoleRow(UUID id, String code, String displayName, String audience) {}
    private record PolicyRow(String permissionCode, String scopeType, boolean defaultScope) {}
    private record SubjectRow(UUID id, String accountType, UUID authAccountId, boolean active, long authorizationVersion) {}
    private record AssignmentRow(UUID id, UUID subjectId, String roleCode) {}
    private record AssignmentViewRow(UUID id, String roleCode, OffsetDateTime validUntil) {}
    private record ScopeRow(String permissionCode, String scopeType) {}
    private record ChangeRequestRow(UUID id, UUID targetSubjectId, UUID requestedBySubjectId,
        String changeType, String status, String payload, long expectedAuthorizationVersion, OffsetDateTime expiresAt) {}
    private record BootstrapState(UUID firstSuperAdminSubjectId, UUID secondApproverSubjectId,
        OffsetDateTime exceptionConsumedAt) {}
    private record Payload(String roleCode, String validUntil, Map<String, Set<Scope>> grants) {}
    private record IdempotentChangeRow(UUID id, UUID targetSubjectId, UUID requestedBySubjectId,
        UUID reviewedBySubjectId, String changeType, String status, String roleCode, String reason,
        String reviewReason, OffsetDateTime expiresAt, OffsetDateTime createdAt, String payload) {
        ChangeRequestView view() { return new ChangeRequestView(id, targetSubjectId, requestedBySubjectId,
            reviewedBySubjectId, changeType, status, roleCode, reason, reviewReason, expiresAt, createdAt); }
    }

    public record Actor(UUID subjectId, UUID profileId, long authorizationVersion) {}
    public record ScopeOverride(String permissionCode, List<Scope> scopes) {}
    public record RetainedScopes(String permissionCode, List<Scope> scopes) {}
    public record ChangeInput(UUID targetSubjectId, String roleCode, List<ScopeOverride> scopeOverrides,
        String validUntil, String reason, long expectedAuthorizationVersion, String idempotencyKey) {}
    public record ReductionInput(UUID assignmentId, List<RetainedScopes> retainedScopes,
        String reason, long expectedAuthorizationVersion) {}
    public record PermissionPolicyView(String permissionCode, List<Scope> allowedScopes, List<Scope> defaultScopes) {}
    public record RoleView(String code, String displayName, String accountType, List<PermissionPolicyView> policies) {}
    public record GrantView(String permissionCode, List<Scope> scopes) {}
    public record AssignmentView(UUID id, String roleCode, String validUntil, List<GrantView> grants) {}
    public record SubjectView(UUID id, String accountType, UUID accountId, UUID profileId, boolean active,
        long authorizationVersion, List<AssignmentView> assignments, List<GrantView> effectiveGrants) {}
    public record ChangeRequestView(UUID id, UUID targetSubjectId, UUID requestedBySubjectId,
        UUID reviewedBySubjectId, String changeType, String status, String roleCode, String reason,
        String reviewReason, OffsetDateTime expiresAt, OffsetDateTime createdAt) {}
    public record AuditView(UUID id, UUID actorSubjectId, UUID targetSubjectId, String action, String reason,
        String correlationId, OffsetDateTime createdAt) {}
}
