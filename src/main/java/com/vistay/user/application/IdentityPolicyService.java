package com.vistay.user.application;

import graphql.GraphqlErrorException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

@Service
public class IdentityPolicyService {
    private final JdbcClient jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public IdentityPolicyService(JdbcClient jdbc, TransactionTemplate transactions, ObjectMapper json) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.json = json;
    }

    public List<IdentityPolicyView> list() {
        return jdbc.sql("""
            SELECT account_type, policy_version, registration_enabled,
                   CASE WHEN requires_approval THEN 'REQUIRE_APPROVAL' ELSE 'AUTO_LINK' END AS link_mode,
                   EXTRACT(EPOCH FROM link_deadline)::bigint AS link_deadline_seconds,
                   EXTRACT(EPOCH FROM otp_ttl)::bigint AS otp_ttl_seconds,
                   max_otp_attempts,
                   EXTRACT(EPOCH FROM disable_grace_period)::bigint AS disable_grace_period_seconds,
                   EXTRACT(EPOCH FROM purge_after)::bigint AS purge_after_seconds,
                   active, updated_at
            FROM profile_link_policies
            ORDER BY CASE account_type WHEN 'CUSTOMER' THEN 1 WHEN 'HOST' THEN 2 ELSE 3 END
            """).query(IdentityPolicyView.class).list();
    }

    public IdentityPolicyView update(UUID actorAccountId, Change change) {
        var type = accountType(change.accountType());
        var mode = linkMode(change.linkMode());
        var reason = reason(change.reason());
        var key = idempotencyKey(change.idempotencyKey());
        if (change.expectedPolicyVersion() < 1) throw error("INVALID_POLICY_VERSION", "Expected policy version must be positive");
        var fingerprint = sha256(String.join("\n", "identity-policy-change-v1", type,
            Boolean.toString(change.registrationEnabled()), mode,
            Long.toString(change.expectedPolicyVersion()), reason));
        var replay = findChange(key);
        if (replay != null) return replay(replay, fingerprint, type);

        try {
            var updated = transactions.execute(status -> {
                var next = jdbc.sql("""
                    UPDATE profile_link_policies
                    SET registration_enabled = :registrationEnabled,
                        requires_approval = :requiresApproval,
                        policy_version = policy_version + 1,
                        updated_at = now(),
                        updated_by_subject_id = (
                            SELECT id FROM authorization_subjects
                            WHERE account_type = 'ADMIN' AND auth_account_id = :actor
                        )
                    WHERE account_type = :type AND policy_version = :expectedVersion AND active
                    RETURNING policy_version
                    """)
                    .param("registrationEnabled", change.registrationEnabled())
                    .param("requiresApproval", "REQUIRE_APPROVAL".equals(mode))
                    .param("actor", actorAccountId).param("type", type)
                    .param("expectedVersion", change.expectedPolicyVersion())
                    .query(Long.class).optional()
                    .orElseThrow(() -> error("STALE_POLICY_VERSION", "Identity policy changed concurrently"));

                jdbc.sql("""
                    INSERT INTO identity_policy_change_requests(
                        idempotency_key, request_hash, account_type,
                        resulting_policy_version, actor_account_id, reason
                    ) VALUES (:key, :hash, :type, :version, :actor, :reason)
                    """).param("key", key).param("hash", fingerprint).param("type", type)
                    .param("version", next).param("actor", actorAccountId).param("reason", reason).update();
                emitChanged(type, next, change.registrationEnabled(), mode, actorAccountId);
                return get(type);
            });
            if (updated == null) throw new IllegalStateException("Identity policy update returned no result");
            return updated;
        } catch (DataIntegrityViolationException conflict) {
            var winner = findChange(key);
            if (winner != null) return replay(winner, fingerprint, type);
            throw conflict;
        }
    }

    private IdentityPolicyView get(String accountType) {
        return list().stream().filter(policy -> policy.accountType().equals(accountType)).findFirst()
            .orElseThrow(() -> error("IDENTITY_POLICY_NOT_FOUND", "Identity policy was not found"));
    }

    private void emitChanged(
        String accountType,
        long policyVersion,
        boolean registrationEnabled,
        String linkMode,
        UUID actorAccountId
    ) {
        var aggregateId = UUID.nameUUIDFromBytes(("vistay:identity-policy:" + accountType)
            .getBytes(StandardCharsets.UTF_8));
        var payload = writeJson(Map.of(
            "accountType", accountType,
            "policyVersion", policyVersion,
            "registrationEnabled", registrationEnabled,
            "linkMode", linkMode,
            "actorAccountId", actorAccountId.toString(),
            "changedAt", OffsetDateTime.now().toString()
        ));
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id
            ) VALUES (
                'IdentityPolicy', :aggregateId, :version,
                'vistay.user.identity-policy-changed', 1,
                CAST(:payload AS jsonb), :correlationId
            )
            """).param("aggregateId", aggregateId).param("version", policyVersion)
            .param("payload", payload).param("correlationId", UUID.randomUUID().toString()).update();
    }

    private PolicyChangeRow findChange(String key) {
        return jdbc.sql("""
            SELECT request_hash, account_type, resulting_policy_version
            FROM identity_policy_change_requests WHERE idempotency_key = :key
            """).param("key", key).query(PolicyChangeRow.class).optional().orElse(null);
    }

    private IdentityPolicyView replay(PolicyChangeRow row, String fingerprint, String type) {
        if (!row.accountType().equals(type)
            || !MessageDigest.isEqual(row.requestHash().getBytes(StandardCharsets.US_ASCII),
                fingerprint.getBytes(StandardCharsets.US_ASCII))) {
            throw error("IDEMPOTENCY_CONFLICT", "Idempotency key was used with a different policy change");
        }
        return get(type);
    }

    private String writeJson(Object value) {
        try { return json.writeValueAsString(value); }
        catch (JacksonException failure) { throw new IllegalStateException("Cannot serialize identity policy event", failure); }
    }

    private static String accountType(String value) {
        var normalized = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("CUSTOMER|HOST|ADMIN")) throw error("INVALID_ACCOUNT_TYPE", "Unsupported account type");
        return normalized;
    }

    private static String linkMode(String value) {
        var normalized = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("AUTO_LINK|REQUIRE_APPROVAL")) throw error("INVALID_LINK_MODE", "Unsupported identity link mode");
        return normalized;
    }

    private static String reason(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.length() < 8 || normalized.length() > 500) throw error("INVALID_REASON", "Reason must contain 8 to 500 characters");
        return normalized;
    }

    private static String idempotencyKey(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 160) throw error("INVALID_IDEMPOTENCY_KEY", "Idempotency key is required");
        return normalized;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static GraphqlErrorException error(String code, String message) {
        return GraphqlErrorException.newErrorException().message(message)
            .errorClassification("IDENTITY_POLICY_NOT_FOUND".equals(code) ? ErrorType.NOT_FOUND : ErrorType.BAD_REQUEST)
            .extensions(Map.of("code", code)).build();
    }

    public record IdentityPolicyView(
        String accountType,
        long policyVersion,
        boolean registrationEnabled,
        String linkMode,
        long linkDeadlineSeconds,
        long otpTtlSeconds,
        int maxOtpAttempts,
        long disableGracePeriodSeconds,
        long purgeAfterSeconds,
        boolean active,
        OffsetDateTime updatedAt
    ) {}

    public record Change(String accountType, boolean registrationEnabled, String linkMode,
                         long expectedPolicyVersion, String reason, String idempotencyKey) {}
    private record PolicyChangeRow(String requestHash, String accountType, long resultingPolicyVersion) {}
}
