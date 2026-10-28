package com.vistay.user.application;

import com.vistay.user.application.AuthorizationSnapshotService.Scope;
import graphql.GraphqlErrorException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

@Service
public class ProfileService {
    private static final Pattern E164 = Pattern.compile("^\\+[1-9][0-9]{7,14}$");

    private final JdbcClient jdbc;
    private final AuthorizationSnapshotService snapshots;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public ProfileService(
        JdbcClient jdbc,
        AuthorizationSnapshotService snapshots,
        TransactionTemplate transactions,
        ObjectMapper json
    ) {
        this.jdbc = jdbc;
        this.snapshots = snapshots;
        this.transactions = transactions;
        this.json = json;
    }

    public PersonalProfile get(UUID accountId) {
        var snapshot = require(accountId, "profile:read");
        return profile(snapshot.profileId(), false);
    }

    public PersonalProfile update(UUID accountId, UpdateProfileInput input) {
        var snapshot = require(accountId, "profile:update");
        var displayName = displayName(input.displayName());
        var phone = phone(input.contactPhone());
        var reason = reason(input.reason());
        var idempotencyKey = idempotencyKey(input.idempotencyKey());
        var requestHash = sha256(String.join("\n",
            accountId.toString(),
            displayName,
            phone == null ? "" : phone,
            input.avatarMediaId() == null ? "" : input.avatarMediaId().toString(),
            Long.toString(input.expectedVersion()),
            reason
        ));

        return transactions.execute(status -> {
            var current = lockedProfile(snapshot.profileId());
            var previous = request(idempotencyKey);
            if (previous != null) {
                if (!MessageDigest.isEqual(
                    previous.requestHash().getBytes(StandardCharsets.US_ASCII),
                    requestHash.getBytes(StandardCharsets.US_ASCII)
                )) {
                    throw error("IDEMPOTENCY_KEY_REUSED", "Idempotency key was reused with different profile data");
                }
                return view(snapshot, previous);
            }
            if (current.version() != input.expectedVersion()) {
                throw error("VERSION_CONFLICT", "Profile was changed by another request");
            }

            var updated = jdbc.sql("""
                UPDATE admin_users
                SET full_name = :displayName,
                    normalized_phone = :phone,
                    avatar_media_id = :avatarMediaId,
                    version = version + 1,
                    updated_at = now()
                WHERE id = :profileId AND version = :expectedVersion
                RETURNING id, auth_account_id, full_name AS display_name, email::text AS email,
                          normalized_phone AS contact_phone, avatar_media_id,
                          version, updated_at
                """)
                .param("displayName", displayName)
                .param("phone", phone)
                .param("avatarMediaId", input.avatarMediaId())
                .param("profileId", snapshot.profileId())
                .param("expectedVersion", input.expectedVersion())
                .query(ProfileRow.class)
                .optional()
                .orElseThrow(() -> error("VERSION_CONFLICT", "Profile was changed by another request"));

            jdbc.sql("""
                INSERT INTO profile_update_requests(
                    idempotency_key, request_hash, admin_user_id,
                    resulting_version, result_display_name, result_email,
                    result_contact_phone, result_avatar_media_id, result_updated_at,
                    correlation_id
                ) VALUES (
                    :key, :hash, :profileId, :version, :displayName, :email,
                    :contactPhone, :avatarMediaId, :updatedAt, :correlationId
                )
                """)
                .param("key", idempotencyKey)
                .param("hash", requestHash)
                .param("profileId", updated.id())
                .param("version", updated.version())
                .param("displayName", updated.displayName())
                .param("email", updated.email())
                .param("contactPhone", updated.contactPhone())
                .param("avatarMediaId", updated.avatarMediaId())
                .param("updatedAt", updated.updatedAt())
                .param("correlationId", idempotencyKey)
                .update();

            jdbc.sql("""
                INSERT INTO audit_events(
                    actor_admin_user_id, action, aggregate_type, aggregate_id,
                    changes, correlation_id, reason
                ) VALUES (
                    :profileId, 'PROFILE_UPDATED', 'AdminProfile', :profileId,
                    CAST(:changes AS jsonb), :correlationId, :reason
                )
                """)
                .param("profileId", updated.id())
                .param("changes", writeJson(Map.of(
                    "displayNameChanged", !current.displayName().equals(updated.displayName()),
                    "contactPhoneChanged", !java.util.Objects.equals(current.contactPhone(), updated.contactPhone()),
                    "avatarReferenceChanged", !java.util.Objects.equals(current.avatarMediaId(), updated.avatarMediaId()),
                    "resultingVersion", updated.version()
                )))
                .param("correlationId", idempotencyKey)
                .param("reason", reason)
                .update();
            return view(updated, false);
        });
    }

    private AuthorizationSnapshotService.Snapshot require(UUID accountId, String permission) {
        var snapshot = snapshots.get("ADMIN", accountId);
        if (!snapshot.active() || snapshot.profileId() == null) {
            throw error("PROFILE_NOT_PROVISIONED", "Backoffice profile is not active or provisioned");
        }
        if (!snapshot.allows(permission, Scope.SELF)) {
            throw error("FORBIDDEN", "Missing permission " + permission + "@SELF");
        }
        return snapshot;
    }

    private ProfileRow lockedProfile(UUID profileId) {
        return jdbc.sql("""
            SELECT id, auth_account_id, full_name AS display_name, email::text AS email,
                   normalized_phone AS contact_phone, avatar_media_id, version, updated_at
            FROM admin_users WHERE id = :profileId FOR UPDATE
            """)
            .param("profileId", profileId)
            .query(ProfileRow.class)
            .optional()
            .orElseThrow(() -> error("PROFILE_NOT_FOUND", "Backoffice profile was not found"));
    }

    private PersonalProfile profile(UUID profileId, boolean replayed) {
        var row = jdbc.sql("""
            SELECT id, auth_account_id, full_name AS display_name, email::text AS email,
                   normalized_phone AS contact_phone, avatar_media_id, version, updated_at
            FROM admin_users WHERE id = :profileId
            """)
            .param("profileId", profileId)
            .query(ProfileRow.class)
            .optional()
            .orElseThrow(() -> error("PROFILE_NOT_FOUND", "Backoffice profile was not found"));
        return view(row, replayed);
    }

    private ProfileUpdateRequest request(String idempotencyKey) {
        return jdbc.sql("""
            SELECT request_hash, resulting_version, result_display_name,
                   result_email, result_contact_phone, result_avatar_media_id,
                   result_updated_at
            FROM profile_update_requests WHERE idempotency_key = :key
            """)
            .param("key", idempotencyKey)
            .query(ProfileUpdateRequest.class)
            .optional()
            .orElse(null);
    }

    private static PersonalProfile view(ProfileRow row, boolean replayed) {
        return new PersonalProfile(
            row.authAccountId(), row.id(), row.displayName(), row.email(), row.contactPhone(),
            row.avatarMediaId(), row.version(), row.updatedAt(), replayed
        );
    }

    private static PersonalProfile view(
        AuthorizationSnapshotService.Snapshot snapshot,
        ProfileUpdateRequest request
    ) {
        return new PersonalProfile(
            snapshot.authAccountId(), snapshot.profileId(), request.resultDisplayName(),
            request.resultEmail(), request.resultContactPhone(), request.resultAvatarMediaId(),
            request.resultingVersion(), request.resultUpdatedAt(), true
        );
    }

    private String writeJson(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JacksonException failure) {
            throw new IllegalStateException("Cannot serialize profile audit", failure);
        }
    }

    private static String displayName(String value) {
        var normalized = value == null ? "" : value.trim().replaceAll("\\s+", " ");
        if (normalized.isEmpty() || normalized.length() > 180) {
            throw error("INVALID_DISPLAY_NAME", "Display name must contain 1 to 180 characters");
        }
        return normalized;
    }

    private static String phone(String value) {
        if (value == null || value.isBlank()) return null;
        var normalized = value.replaceAll("[\\s().-]", "");
        if (!E164.matcher(normalized).matches()) {
            throw error("INVALID_CONTACT_PHONE", "Contact phone must use E.164 format");
        }
        return normalized;
    }

    private static String reason(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.length() < 8 || normalized.length() > 500) {
            throw error("INVALID_REASON", "Reason must contain 8 to 500 characters");
        }
        return normalized;
    }

    private static String idempotencyKey(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 160) {
            throw error("INVALID_IDEMPOTENCY_KEY", "Idempotency key must contain 1 to 160 characters");
        }
        return normalized;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static GraphqlErrorException error(String code, String message) {
        var classification = switch (code) {
            case "PROFILE_NOT_FOUND" -> ErrorType.NOT_FOUND;
            case "FORBIDDEN" -> ErrorType.FORBIDDEN;
            default -> ErrorType.BAD_REQUEST;
        };
        return GraphqlErrorException.newErrorException()
            .message(message)
            .errorClassification(classification)
            .extensions(Map.of("code", code))
            .build();
    }

    private record ProfileRow(
        UUID id,
        UUID authAccountId,
        String displayName,
        String email,
        String contactPhone,
        UUID avatarMediaId,
        long version,
        OffsetDateTime updatedAt
    ) {}

    private record ProfileUpdateRequest(
        String requestHash,
        long resultingVersion,
        String resultDisplayName,
        String resultEmail,
        String resultContactPhone,
        UUID resultAvatarMediaId,
        OffsetDateTime resultUpdatedAt
    ) {}

    public record UpdateProfileInput(
        String displayName,
        String contactPhone,
        UUID avatarMediaId,
        long expectedVersion,
        String reason,
        String idempotencyKey
    ) {}

    public record PersonalProfile(
        UUID accountId,
        UUID profileId,
        String displayName,
        String email,
        String contactPhone,
        UUID avatarMediaId,
        long version,
        OffsetDateTime updatedAt,
        boolean replayed
    ) {}
}
