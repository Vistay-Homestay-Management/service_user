package com.vistay.user.application;

import graphql.GraphqlErrorException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import com.vistay.user.application.AuthorizationSnapshotService.Scope;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

@Service
public class LoyaltyProgramService {
    private static final Pattern CODE = Pattern.compile("^[a-z][a-z0-9-]{1,63}$");
    private final JdbcClient jdbc;
    private final ObjectMapper json;
    private final AuthorizationManagementService authorization;

    public LoyaltyProgramService(JdbcClient jdbc, ObjectMapper json,
        AuthorizationManagementService authorization) {
        this.jdbc = jdbc;
        this.json = json;
        this.authorization = authorization;
    }

    @Transactional(readOnly = true)
    public List<ProgramView> catalog(UUID actorAccountId) {
        authorization.requireActor(actorAccountId, "loyalty-program:read");
        return jdbc.sql("""
                SELECT id, code, name, scope_type, scope_id, active, row_version
                FROM loyalty_programs ORDER BY active DESC, code
                """).query(ProgramRow.class).list().stream().map(this::view).toList();
    }

    @Transactional(readOnly = true)
    public List<ChangeRequestView> changeRequests(UUID actorAccountId, String status) {
        authorization.requireActor(actorAccountId, "loyalty-program:read");
        var normalized = status == null || status.isBlank() ? null : status.trim().toUpperCase();
        return jdbc.sql("""
                SELECT id, program_code, expected_program_version, requested_by_subject_id,
                       reviewed_by_subject_id, status, reason, review_reason, created_at, reviewed_at
                FROM loyalty_program_change_requests
                WHERE (:status IS NULL OR status = :status)
                ORDER BY created_at DESC
                """).param("status", normalized).query(ChangeRequestView.class).list();
    }

    @Transactional(readOnly = true)
    public LoyaltyProfile myProfile(UUID customerAccountId) {
        var actor = authorization.requireActor("CUSTOMER", customerAccountId,
            "loyalty-profile:read", Scope.SELF);
        var subjectId = jdbc.sql("""
                SELECT id FROM authorization_subjects
                WHERE account_type = 'CUSTOMER' AND auth_account_id = :accountId AND active
                """).param("accountId", customerAccountId).query(UUID.class).optional()
            .orElseThrow(() -> error("CUSTOMER_PROFILE_NOT_FOUND", "Customer profile was not found"));
        if (!actor.subjectId().equals(subjectId)) {
            throw error("LOYALTY_PROFILE_FORBIDDEN", "Only the current customer loyalty profile can be read");
        }
        return profile(subjectId);
    }

    @Transactional
    public ChangeRequestView requestChange(UUID actorAccountId, ProgramChangeInput input) {
        var actor = authorization.requireActor(actorAccountId, "loyalty-program:change-request");
        validate(input);
        var payload = write(input);
        var hash = sha256(payload);
        var existing = jdbc.sql("""
                SELECT id, request_hash FROM loyalty_program_change_requests
                WHERE requested_by_subject_id = :actor AND idempotency_key = :key
                """).param("actor", actor.subjectId()).param("key", input.idempotencyKey())
            .query(IdempotencyRow.class).optional().orElse(null);
        if (existing != null) {
            if (!existing.requestHash().equals(hash)) {
                throw error("IDEMPOTENCY_CONFLICT", "Idempotency key was used for another request");
            }
            return request(existing.id());
        }
        var id = jdbc.sql("""
                INSERT INTO loyalty_program_change_requests(
                    program_code, expected_program_version, requested_by_subject_id,
                    requested_payload, request_hash, reason, idempotency_key)
                VALUES (:code, :expectedVersion, :actor, CAST(:payload AS jsonb),
                        :hash, :reason, :key)
                RETURNING id
                """).param("code", input.code()).param("expectedVersion", input.expectedVersion())
            .param("actor", actor.subjectId()).param("payload", payload).param("hash", hash)
            .param("reason", input.reason().trim()).param("key", input.idempotencyKey().trim())
            .query(UUID.class).single();
        return request(id);
    }

    @Transactional
    public ChangeRequestView approve(UUID actorAccountId, UUID requestId, String reason) {
        var actor = authorization.requireActor(actorAccountId, "loyalty-program:change-approve");
        requireReason(reason);
        var change = jdbc.sql("""
                SELECT id, program_code, expected_program_version, requested_by_subject_id,
                       status, requested_payload::text AS payload
                FROM loyalty_program_change_requests WHERE id = :id FOR UPDATE
                """).param("id", requestId).query(ChangeRow.class).optional()
            .orElseThrow(() -> error("LOYALTY_CHANGE_NOT_FOUND", "Loyalty change request was not found"));
        if (!"PENDING".equals(change.status())) {
            throw error("LOYALTY_CHANGE_NOT_PENDING", "Loyalty change request is not pending");
        }
        if (change.requestedBySubjectId().equals(actor.subjectId())) {
            throw error("MAKER_CHECKER_VIOLATION", "Requester cannot approve the same change");
        }
        var input = read(change.payload());
        var program = lockProgram(input.code());
        if (program == null) {
            if (input.expectedVersion() != null) {
                return stale(change.id(), actor.subjectId(), reason);
            }
            program = jdbc.sql("""
                    INSERT INTO loyalty_programs(code, name, scope_type, scope_id)
                    VALUES (:code, :name, :scopeType, :scopeId)
                    RETURNING id, code, name, scope_type, scope_id, active, row_version
                    """).param("code", input.code()).param("name", input.name().trim())
                .param("scopeType", input.scopeType()).param("scopeId", input.scopeId())
                .query(ProgramRow.class).single();
        } else {
            if (input.expectedVersion() == null || program.rowVersion() != input.expectedVersion()) {
                return stale(change.id(), actor.subjectId(), reason);
            }
            program = jdbc.sql("""
                    UPDATE loyalty_programs SET name = :name, row_version = row_version + 1,
                        updated_at = now()
                    WHERE id = :id
                    RETURNING id, code, name, scope_type, scope_id, active, row_version
                    """).param("name", input.name().trim()).param("id", program.id())
                .query(ProgramRow.class).single();
        }
        var nextVersion = jdbc.sql("""
                SELECT COALESCE(MAX(version), 0) + 1 FROM loyalty_program_versions
                WHERE program_id = :programId
                """).param("programId", program.id()).query(Integer.class).single();
        var effectiveFrom = OffsetDateTime.parse(input.effectiveFrom()).withOffsetSameInstant(ZoneOffset.UTC);
        jdbc.sql("""
                UPDATE loyalty_program_versions SET effective_to = :effectiveFrom
                WHERE program_id = :programId AND status = 'ACTIVE'
                  AND effective_from < :effectiveFrom
                  AND (effective_to IS NULL OR effective_to > :effectiveFrom)
                """).param("effectiveFrom", effectiveFrom).param("programId", program.id()).update();
        var status = effectiveFrom.isAfter(OffsetDateTime.now(ZoneOffset.UTC)) ? "SCHEDULED" : "ACTIVE";
        var fingerprint = sha256(write(Map.of(
            "program", input.code(), "version", nextVersion, "tiers", input.tiers(),
            "earningRules", input.earningRules(), "window", input.qualificationWindow(),
            "rollingDays", input.rollingWindowDays() == null ? 0 : input.rollingWindowDays())));
        var versionId = jdbc.sql("""
                INSERT INTO loyalty_program_versions(program_id, version, status,
                    qualification_window, rolling_window_days, effective_from, effective_to,
                    payload, fingerprint, requested_by_subject_id, approved_by_subject_id,
                    reason, approved_at)
                VALUES (:programId, :version, :status, :window, :rollingDays, :effectiveFrom,
                    :effectiveTo, CAST(:payload AS jsonb), :fingerprint, :requester,
                    :approver, :reason, now()) RETURNING id
                """).param("programId", program.id()).param("version", nextVersion)
            .param("status", status).param("window", input.qualificationWindow())
            .param("rollingDays", input.rollingWindowDays()).param("effectiveFrom", effectiveFrom)
            .param("effectiveTo", parseOptional(input.effectiveTo())).param("payload", write(input))
            .param("fingerprint", fingerprint).param("requester", change.requestedBySubjectId())
            .param("approver", actor.subjectId()).param("reason", input.reason().trim())
            .query(UUID.class).single();
        for (var tier : input.tiers()) {
            jdbc.sql("""
                    INSERT INTO loyalty_tier_bands(program_version_id, code, display_name,
                        minimum_points, display_order, presentation)
                    VALUES (:versionId, :code, :name, :minimumPoints, :displayOrder,
                        CAST(:presentation AS jsonb))
                    """).param("versionId", versionId).param("code", tier.code())
                .param("name", tier.displayName().trim()).param("minimumPoints", tier.minimumPoints())
                .param("displayOrder", tier.displayOrder())
                .param("presentation", write(tier.presentation() == null ? Map.of() : tier.presentation()))
                .update();
        }
        for (var rule : input.earningRules() == null ? List.<EarningRuleInput>of() : input.earningRules()) {
            jdbc.sql("""
                    INSERT INTO loyalty_earning_rules(program_version_id, code, rule_type,
                        points, amount_block, conditions, priority)
                    VALUES (:versionId, :code, :type, :points, :amountBlock,
                        CAST(:conditions AS jsonb), :priority)
                    """).param("versionId", versionId).param("code", rule.code())
                .param("type", rule.ruleType()).param("points", rule.points())
                .param("amountBlock", rule.amountBlock())
                .param("conditions", write(rule.conditions() == null ? Map.of() : rule.conditions()))
                .param("priority", rule.priority()).update();
        }
        jdbc.sql("""
                UPDATE loyalty_program_change_requests SET status = 'APPROVED',
                    reviewed_by_subject_id = :reviewer, review_reason = :reason,
                    reviewed_at = now() WHERE id = :id
                """).param("reviewer", actor.subjectId()).param("reason", reason.trim())
            .param("id", change.id()).update();
        emit(program.id(), nextVersion, "vistay.user.loyalty-policy-published");
        return request(change.id());
    }

    @Transactional
    public ChangeRequestView reject(UUID actorAccountId, UUID requestId, String reason) {
        var actor = authorization.requireActor(actorAccountId, "loyalty-program:change-approve");
        requireReason(reason);
        var changed = jdbc.sql("""
                UPDATE loyalty_program_change_requests SET status = 'REJECTED',
                    reviewed_by_subject_id = :reviewer, review_reason = :reason,
                    reviewed_at = now()
                WHERE id = :id AND status = 'PENDING'
                  AND requested_by_subject_id <> :reviewer
                """).param("reviewer", actor.subjectId()).param("reason", reason.trim())
            .param("id", requestId).update();
        if (changed != 1) throw error("LOYALTY_CHANGE_NOT_PENDING", "Request cannot be rejected");
        return request(requestId);
    }

    @Transactional
    public LoyaltyProfile adjustPoints(UUID actorAccountId, PointAdjustmentInput input) {
        var actor = authorization.requireActor(actorAccountId, "loyalty-point:adjust");
        requireReason(input.reason());
        requireKey(input.idempotencyKey());
        if (input.delta() == 0) throw error("INVALID_POINT_DELTA", "Point delta cannot be zero");
        var subjectId = jdbc.sql("""
                SELECT id FROM authorization_subjects
                WHERE account_type = 'CUSTOMER' AND auth_account_id = :accountId AND active
                """).param("accountId", input.customerAccountId()).query(UUID.class).optional()
            .orElseThrow(() -> error("CUSTOMER_PROFILE_NOT_FOUND", "Customer profile was not found"));
        var existing = jdbc.sql("""
                SELECT id FROM loyalty_point_ledger
                WHERE customer_subject_id = :subjectId AND idempotency_key = :key
                """).param("subjectId", subjectId).param("key", input.idempotencyKey())
            .query(UUID.class).optional();
        if (existing.isPresent()) return refreshProjection(subjectId);
        var policy = effectiveProgramVersion();
        var current = points(subjectId, policy);
        if (current + input.delta() < 0) {
            throw error("NEGATIVE_QUALIFYING_POINTS", "Adjustment cannot make points negative");
        }
        jdbc.sql("""
                INSERT INTO loyalty_point_ledger(customer_subject_id, program_version_id,
                    source_type, source_id, source_revision, delta, reason, idempotency_key,
                    created_by_subject_id, occurred_at)
                VALUES (:subjectId, :programVersionId, 'ADMIN_ADJUSTMENT', :sourceId, 1,
                    :delta, :reason, :key, :actor, now())
                """).param("subjectId", subjectId).param("programVersionId", policy.id())
            .param("sourceId", input.idempotencyKey()).param("delta", input.delta())
            .param("reason", input.reason().trim()).param("key", input.idempotencyKey().trim())
            .param("actor", actor.subjectId()).update();
        return refreshProjection(subjectId);
    }

    private LoyaltyProfile profile(UUID subjectId) {
        try {
            return refreshProjection(subjectId);
        } catch (GraphqlErrorException unavailable) {
            if (unavailable.getExtensions() != null
                && "LOYALTY_PROGRAM_UNAVAILABLE".equals(unavailable.getExtensions().get("code"))) {
                return new LoyaltyProfile("UNAVAILABLE", 0, null, null, null, null,
                    OffsetDateTime.now(ZoneOffset.UTC).toString());
            }
            throw unavailable;
        }
    }

    private LoyaltyProfile refreshProjection(UUID subjectId) {
        var policy = effectiveProgramVersion();
        var total = points(subjectId, policy);
        var tiers = tiers(policy.id());
        var current = tiers.stream().filter(t -> t.minimumPoints() <= total)
            .reduce((left, right) -> right)
            .orElseThrow(() -> error("INVALID_LOYALTY_POLICY", "Active policy has no zero-point tier"));
        var next = tiers.stream().filter(t -> t.minimumPoints() > total).findFirst().orElse(null);
        var now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbc.sql("""
                INSERT INTO customer_loyalty_projections(customer_subject_id, program_version_id,
                    qualifying_points, tier_code, source_watermark)
                VALUES (:subjectId, :programVersionId, :points, :tierCode, :watermark)
                ON CONFLICT (customer_subject_id) DO UPDATE SET
                    program_version_id = EXCLUDED.program_version_id,
                    qualifying_points = EXCLUDED.qualifying_points,
                    tier_code = EXCLUDED.tier_code,
                    source_watermark = EXCLUDED.source_watermark,
                    projection_version = customer_loyalty_projections.projection_version + 1,
                    updated_at = now()
                """).param("subjectId", subjectId).param("programVersionId", policy.id())
            .param("points", total).param("tierCode", current.code()).param("watermark", now).update();
        return new LoyaltyProfile("ASSESSED", total, current,
            next, next == null ? null : next.minimumPoints() - total,
            policy.version(), now.toString());
    }

    private long points(UUID subjectId, VersionRow policy) {
        var sql = """
            SELECT COALESCE(SUM(delta), 0) FROM loyalty_point_ledger
            WHERE customer_subject_id = :subjectId
              AND (expires_at IS NULL OR expires_at > now())
            """ + ("ROLLING_DAYS".equals(policy.qualificationWindow())
            ? " AND occurred_at >= now() - make_interval(days => :days)" : "");
        var query = jdbc.sql(sql).param("subjectId", subjectId);
        if ("ROLLING_DAYS".equals(policy.qualificationWindow())) {
            query = query.param("days", policy.rollingWindowDays());
        }
        return query.query(Long.class).single();
    }

    private VersionRow effectiveProgramVersion() {
        return jdbc.sql("""
                SELECT v.id, v.version, v.qualification_window, v.rolling_window_days
                FROM loyalty_program_versions v JOIN loyalty_programs p ON p.id = v.program_id
                WHERE p.active AND v.status IN ('ACTIVE', 'SCHEDULED')
                  AND v.effective_from <= now()
                  AND (v.effective_to IS NULL OR v.effective_to > now())
                ORDER BY CASE p.scope_type WHEN 'ORGANIZATION' THEN 0 ELSE 1 END,
                         v.effective_from DESC LIMIT 1
                """).query(VersionRow.class).optional()
            .orElseThrow(() -> error("LOYALTY_PROGRAM_UNAVAILABLE", "No loyalty program is effective"));
    }

    private List<TierView> tiers(UUID versionId) {
        return jdbc.sql("""
                SELECT code, display_name, minimum_points, display_order
                FROM loyalty_tier_bands WHERE program_version_id = :versionId
                ORDER BY minimum_points, display_order
                """).param("versionId", versionId).query(TierView.class).list();
    }

    private ProgramView view(ProgramRow row) {
        var versions = jdbc.sql("""
                SELECT id, version, status, qualification_window, rolling_window_days,
                       effective_from, effective_to, fingerprint
                FROM loyalty_program_versions WHERE program_id = :programId
                ORDER BY version DESC
                """).param("programId", row.id()).query((rs, ignored) -> new ProgramVersionView(
                    rs.getObject("id", UUID.class), rs.getInt("version"), rs.getString("status"),
                    rs.getString("qualification_window"), (Integer) rs.getObject("rolling_window_days"),
                    rs.getObject("effective_from", OffsetDateTime.class).toString(),
                    rs.getObject("effective_to", OffsetDateTime.class) == null ? null
                        : rs.getObject("effective_to", OffsetDateTime.class).toString(),
                    rs.getString("fingerprint").trim(),
                    tiers(rs.getObject("id", UUID.class)))).list();
        return new ProgramView(row.id(), row.code(), row.name(), row.scopeType(), row.scopeId(),
            row.active(), row.rowVersion(), versions);
    }

    private ProgramRow lockProgram(String code) {
        return jdbc.sql("""
                SELECT id, code, name, scope_type, scope_id, active, row_version
                FROM loyalty_programs WHERE code = :code FOR UPDATE
                """).param("code", code).query(ProgramRow.class).optional().orElse(null);
    }

    private ChangeRequestView request(UUID id) {
        return jdbc.sql("""
                SELECT id, program_code, expected_program_version, requested_by_subject_id,
                       reviewed_by_subject_id, status, reason, review_reason, created_at, reviewed_at
                FROM loyalty_program_change_requests WHERE id = :id
                """).param("id", id).query(ChangeRequestView.class).single();
    }

    private ChangeRequestView stale(UUID id, UUID reviewer, String reason) {
        jdbc.sql("""
                UPDATE loyalty_program_change_requests SET status = 'STALE',
                    reviewed_by_subject_id = :reviewer, review_reason = :reason,
                    reviewed_at = now() WHERE id = :id
                """).param("reviewer", reviewer).param("reason", reason.trim()).param("id", id).update();
        return request(id);
    }

    private void emit(UUID aggregateId, long version, String type) {
        jdbc.sql("""
                INSERT INTO outbox_events(aggregate_type, aggregate_id, aggregate_version,
                    event_type, event_version, payload)
                VALUES ('LoyaltyProgram', :id, :version, :type, 1,
                    jsonb_build_object('programId', :id, 'version', :version))
                """).param("id", aggregateId).param("version", version).param("type", type).update();
    }

    private static void validate(ProgramChangeInput input) {
        if (input == null || input.code() == null || !CODE.matcher(input.code()).matches()) {
            throw error("INVALID_LOYALTY_PROGRAM", "Program code must be kebab-case");
        }
        if (input.name() == null || input.name().isBlank()) {
            throw error("INVALID_LOYALTY_PROGRAM", "Program name is required");
        }
        if (!List.of("GLOBAL", "ORGANIZATION").contains(input.scopeType())
            || ("GLOBAL".equals(input.scopeType()) && input.scopeId() != null)
            || ("ORGANIZATION".equals(input.scopeType()) && input.scopeId() == null)) {
            throw error("INVALID_LOYALTY_SCOPE", "Program scope is invalid");
        }
        if (!List.of("LIFETIME", "ROLLING_DAYS").contains(input.qualificationWindow())
            || ("LIFETIME".equals(input.qualificationWindow()) && input.rollingWindowDays() != null)
            || ("ROLLING_DAYS".equals(input.qualificationWindow())
                && (input.rollingWindowDays() == null || input.rollingWindowDays() < 30
                    || input.rollingWindowDays() > 3650))) {
            throw error("INVALID_LOYALTY_WINDOW", "Qualification window is invalid");
        }
        requireReason(input.reason());
        requireKey(input.idempotencyKey());
        try {
            var from = OffsetDateTime.parse(input.effectiveFrom());
            var to = parseOptional(input.effectiveTo());
            if (to != null && !to.isAfter(from)) throw new IllegalArgumentException();
        } catch (RuntimeException invalid) {
            throw error("INVALID_LOYALTY_EFFECTIVE_RANGE", "Effective range must use ISO-8601");
        }
        if (input.tiers() == null || input.tiers().isEmpty()
            || input.tiers().stream().noneMatch(tier -> tier.minimumPoints() == 0)) {
            throw error("INVALID_LOYALTY_TIERS", "At least one zero-point tier is required");
        }
        var codes = new java.util.HashSet<String>();
        var thresholds = new java.util.HashSet<Long>();
        for (var tier : input.tiers()) {
            if (tier.code() == null || !CODE.matcher(tier.code()).matches()
                || tier.displayName() == null || tier.displayName().isBlank()
                || tier.minimumPoints() < 0 || !codes.add(tier.code())
                || !thresholds.add(tier.minimumPoints())) {
                throw error("INVALID_LOYALTY_TIERS", "Tier codes and thresholds must be unique and valid");
            }
        }
    }

    private ProgramChangeInput read(String payload) {
        try { return json.readValue(payload, ProgramChangeInput.class); }
        catch (JacksonException invalid) { throw error("INVALID_LOYALTY_PAYLOAD", "Stored request is invalid"); }
    }

    private String write(Object value) {
        try { return json.writeValueAsString(value); }
        catch (JacksonException failure) { throw new IllegalStateException("Cannot serialize loyalty policy", failure); }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static OffsetDateTime parseOptional(String value) {
        return value == null || value.isBlank() ? null
            : OffsetDateTime.parse(value).withOffsetSameInstant(ZoneOffset.UTC);
    }

    private static void requireReason(String value) {
        if (value == null || value.trim().length() < 8) {
            throw error("INVALID_REASON", "Reason must contain at least 8 characters");
        }
    }

    private static void requireKey(String value) {
        if (value == null || value.isBlank() || value.length() > 160) {
            throw error("INVALID_IDEMPOTENCY_KEY", "Idempotency key is required");
        }
    }

    private static GraphqlErrorException error(String code, String message) {
        return GraphqlErrorException.newErrorException().errorClassification(ErrorType.BAD_REQUEST)
            .message(message).extensions(Map.of("code", code)).build();
    }

    private record ProgramRow(UUID id, String code, String name, String scopeType, UUID scopeId,
        boolean active, long rowVersion) {}
    private record VersionRow(UUID id, int version, String qualificationWindow,
        Integer rollingWindowDays) {}
    private record ChangeRow(UUID id, String programCode, Long expectedProgramVersion,
        UUID requestedBySubjectId, String status, String payload) {}
    private record IdempotencyRow(UUID id, String requestHash) {}

    public record TierInput(String code, String displayName, long minimumPoints,
        int displayOrder, Map<String, Object> presentation) {}
    public record EarningRuleInput(String code, String ruleType, long points,
        String amountBlock, Map<String, Object> conditions, int priority) {}
    public record ProgramChangeInput(String code, String name, String scopeType, UUID scopeId,
        String qualificationWindow, Integer rollingWindowDays, String effectiveFrom,
        String effectiveTo, Long expectedVersion, List<TierInput> tiers,
        List<EarningRuleInput> earningRules, String reason, String idempotencyKey) {}
    public record PointAdjustmentInput(UUID customerAccountId, long delta, String reason,
        String idempotencyKey) {}
    public record TierView(String code, String displayName, long minimumPoints, int displayOrder) {}
    public record ProgramVersionView(UUID id, int version, String status,
        String qualificationWindow, Integer rollingWindowDays, String effectiveFrom,
        String effectiveTo, String fingerprint, List<TierView> tiers) {}
    public record ProgramView(UUID id, String code, String name, String scopeType, UUID scopeId,
        boolean active, long rowVersion, List<ProgramVersionView> versions) {}
    public record LoyaltyProfile(String status, long qualifyingPoints, TierView currentTier,
        TierView nextTier, Long pointsToNextTier, Integer policyVersion, String asOf) {}
    public record ChangeRequestView(UUID id, String programCode, Long expectedProgramVersion,
        UUID requestedBySubjectId, UUID reviewedBySubjectId, String status, String reason,
        String reviewReason, OffsetDateTime createdAt, OffsetDateTime reviewedAt) {}
}
