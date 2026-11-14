package com.vistay.user.application;

import graphql.GraphqlErrorException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.HexFormat;
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
public class ProfileAdministrationService {
    private final JdbcClient jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public ProfileAdministrationService(
        JdbcClient jdbc,
        TransactionTemplate transactions,
        ObjectMapper json
    ) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.json = json;
    }

    public ProfileView createCustomer(UUID actorAccountId, CustomerDraft draft) {
        var normalized = new NormalizedDraft(
            "CUSTOMER", name(draft.fullName()), email(draft.email()), phone(draft.contactPhone()),
            null, null, null, date(draft.dateOfBirth()), text(draft.address(), 500), null,
            reason(draft.reason()), key(draft.idempotencyKey())
        );
        return create(actorAccountId, normalized);
    }

    public ProfileView createAdmin(UUID actorAccountId, AdminDraft draft) {
        var subtype = enumValue(draft.subtype(), "STAFF|RECEPTIONIST|CTV|MANAGER|ADMIN", "INVALID_ADMIN_SUBTYPE");
        var normalized = new NormalizedDraft(
            "ADMIN", name(draft.fullName()), email(draft.email()), phone(draft.contactPhone()),
            code(draft.employeeCode()), subtype, null, date(draft.hiredOn()), null, null,
            reason(draft.reason()), key(draft.idempotencyKey())
        );
        return create(actorAccountId, normalized);
    }

    public ProfileView createHost(UUID actorAccountId, HostDraft draft) {
        var normalized = new NormalizedDraft(
            "HOST", name(draft.fullName()), email(draft.email()), phone(draft.contactPhone()),
            code(draft.hostCode()), null, "UNVERIFIED", null, text(draft.address(), 500),
            text(draft.taxCode(), 40), reason(draft.reason()), key(draft.idempotencyKey())
        );
        return create(actorAccountId, normalized);
    }

    public ProfileView find(String accountType, UUID profileId) {
        var type = accountType(accountType);
        return switch (type) {
            case "CUSTOMER" -> jdbc.sql("""
                SELECT id AS profile_id, auth_account_id AS account_id, 'CUSTOMER' AS account_type,
                       full_name AS display_name, email::text AS email, normalized_phone AS contact_phone,
                       profile_status AS status, NULL::varchar AS reference_code, NULL::varchar AS subtype,
                       NULL::varchar AS verification_status, date_of_birth AS relevant_date,
                       address, NULL::varchar AS tax_code, version, created_at, updated_at
                FROM customers WHERE id = :id
                """).param("id", profileId).query(ProfileView.class).optional()
                .orElseThrow(() -> error("PROFILE_NOT_FOUND", "Customer profile was not found"));
            case "ADMIN" -> jdbc.sql("""
                SELECT id AS profile_id, auth_account_id AS account_id, 'ADMIN' AS account_type,
                       full_name AS display_name, email::text AS email, normalized_phone AS contact_phone,
                       profile_status AS status, employee_code AS reference_code, user_type AS subtype,
                       NULL::varchar AS verification_status, hired_on AS relevant_date,
                       NULL::varchar AS address, NULL::varchar AS tax_code, version, created_at, updated_at
                FROM admin_users WHERE id = :id
                """).param("id", profileId).query(ProfileView.class).optional()
                .orElseThrow(() -> error("PROFILE_NOT_FOUND", "Admin profile was not found"));
            case "HOST" -> jdbc.sql("""
                SELECT id AS profile_id, auth_account_id AS account_id, 'HOST' AS account_type,
                       full_name AS display_name, email::text AS email, normalized_phone AS contact_phone,
                       profile_status AS status, host_code AS reference_code, NULL::varchar AS subtype,
                       verification_status, NULL::date AS relevant_date,
                       address, tax_code, version, created_at, updated_at
                FROM hosts WHERE id = :id
                """).param("id", profileId).query(ProfileView.class).optional()
                .orElseThrow(() -> error("PROFILE_NOT_FOUND", "Host profile was not found"));
            default -> throw new IllegalStateException("Unsupported profile type");
        };
    }

    private ProfileView create(UUID actorAccountId, NormalizedDraft draft) {
        if (actorAccountId == null) throw error("UNAUTHENTICATED", "Actor account is required");
        var fingerprint = sha256(String.join("\n",
            "profile-create-v1", draft.accountType(), draft.fullName(), nullToEmpty(draft.email()),
            nullToEmpty(draft.phone()), nullToEmpty(draft.referenceCode()), nullToEmpty(draft.subtype()),
            nullToEmpty(draft.relevantDate()), nullToEmpty(draft.address()), nullToEmpty(draft.taxCode()),
            draft.reason()
        ));
        var replay = findRequest(draft.idempotencyKey());
        if (replay != null) return replay(replay, fingerprint, draft.accountType());

        try {
            var created = transactions.execute(status -> {
                var profileId = insertProfile(draft);
                jdbc.sql("""
                    INSERT INTO profile_creation_requests(
                        idempotency_key, request_hash, profile_type, profile_id,
                        actor_account_id, reason
                    ) VALUES (:key, :hash, :type, :profileId, :actor, :reason)
                    """)
                    .param("key", draft.idempotencyKey()).param("hash", fingerprint)
                    .param("type", draft.accountType()).param("profileId", profileId)
                    .param("actor", actorAccountId).param("reason", draft.reason()).update();
                emitCreated(profileId, draft.accountType(), actorAccountId);
                return find(draft.accountType(), profileId);
            });
            if (created == null) throw new IllegalStateException("Profile creation returned no result");
            return created;
        } catch (DataIntegrityViolationException conflict) {
            var winner = findRequest(draft.idempotencyKey());
            if (winner != null) return replay(winner, fingerprint, draft.accountType());
            throw error("PROFILE_CONFLICT", "Email or reference code already belongs to another profile");
        }
    }

    private UUID insertProfile(NormalizedDraft draft) {
        return switch (draft.accountType()) {
            case "CUSTOMER" -> jdbc.sql("""
                INSERT INTO customers(full_name, email, normalized_phone, date_of_birth, address, profile_status, version)
                VALUES (:name, :email, :phone, :date, :address, 'ACTIVE', 1)
                RETURNING id
                """).param("name", draft.fullName()).param("email", draft.email())
                .param("phone", draft.phone()).param("date", draft.relevantDate())
                .param("address", draft.address()).query(UUID.class).single();
            case "ADMIN" -> jdbc.sql("""
                INSERT INTO admin_users(employee_code, full_name, email, normalized_phone, user_type, hired_on, profile_status, version)
                VALUES (:code, :name, :email, :phone, :subtype, :date, 'ACTIVE', 1)
                RETURNING id
                """).param("code", draft.referenceCode()).param("name", draft.fullName())
                .param("email", draft.email()).param("phone", draft.phone())
                .param("subtype", draft.subtype()).param("date", draft.relevantDate())
                .query(UUID.class).single();
            case "HOST" -> jdbc.sql("""
                INSERT INTO hosts(host_code, full_name, email, normalized_phone, address, tax_code,
                                  profile_status, verification_status, version)
                VALUES (:code, :name, :email, :phone, :address, :taxCode, 'ACTIVE', 'UNVERIFIED', 1)
                RETURNING id
                """).param("code", draft.referenceCode()).param("name", draft.fullName())
                .param("email", draft.email()).param("phone", draft.phone())
                .param("address", draft.address()).param("taxCode", draft.taxCode())
                .query(UUID.class).single();
            default -> throw new IllegalStateException("Unsupported profile type");
        };
    }

    private void emitCreated(UUID profileId, String accountType, UUID actorAccountId) {
        var payload = writeJson(Map.of(
            "profileId", profileId.toString(),
            "accountType", accountType,
            "actorAccountId", actorAccountId.toString(),
            "accountLinked", false,
            "createdAt", OffsetDateTime.now().toString()
        ));
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id
            ) VALUES (
                'UserProfile', :profileId, 1, 'vistay.user.profile-created',
                1, CAST(:payload AS jsonb), :correlationId
            )
            """).param("profileId", profileId).param("payload", payload)
            .param("correlationId", UUID.randomUUID().toString()).update();
    }

    private CreationRequest findRequest(String idempotencyKey) {
        return jdbc.sql("""
            SELECT request_hash, profile_type, profile_id
            FROM profile_creation_requests WHERE idempotency_key = :key
            """).param("key", idempotencyKey).query(CreationRequest.class).optional().orElse(null);
    }

    private ProfileView replay(CreationRequest request, String fingerprint, String accountType) {
        if (!request.profileType().equals(accountType)
            || !MessageDigest.isEqual(request.requestHash().getBytes(StandardCharsets.US_ASCII),
                fingerprint.getBytes(StandardCharsets.US_ASCII))) {
            throw error("IDEMPOTENCY_CONFLICT", "Idempotency key was used with different profile data");
        }
        return find(accountType, request.profileId());
    }

    private String writeJson(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JacksonException failure) {
            throw new IllegalStateException("Cannot serialize profile event", failure);
        }
    }

    private static String accountType(String value) {
        var type = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!type.matches("CUSTOMER|ADMIN|HOST")) throw error("INVALID_ACCOUNT_TYPE", "Unsupported account type");
        return type;
    }

    private static String name(String value) {
        var normalized = value == null ? "" : value.trim().replaceAll("\\s+", " ");
        if (normalized.isEmpty() || normalized.length() > 180) throw error("INVALID_DISPLAY_NAME", "Display name must contain 1 to 180 characters");
        return normalized;
    }

    private static String email(String value) {
        if (value == null || value.isBlank()) return null;
        var normalized = value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$") || normalized.length() > 320) throw error("INVALID_EMAIL", "Email is invalid");
        return normalized;
    }

    private static String phone(String value) {
        if (value == null || value.isBlank()) return null;
        var normalized = value.trim().replaceAll("[\\s().-]", "");
        if (!normalized.matches("^\\+?[0-9]{8,15}$")) throw error("INVALID_PHONE", "Phone number is invalid");
        return normalized;
    }

    private static String code(String value) {
        if (value == null || value.isBlank()) return null;
        var normalized = value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("^[A-Z0-9_-]{2,40}$")) throw error("INVALID_REFERENCE_CODE", "Reference code is invalid");
        return normalized;
    }

    private static String text(String value, int max) {
        if (value == null || value.isBlank()) return null;
        var normalized = value.trim();
        if (normalized.length() > max) throw error("INVALID_PROFILE_FIELD", "Profile field is too long");
        return normalized;
    }

    private static LocalDate date(String value) {
        if (value == null || value.isBlank()) return null;
        try { return LocalDate.parse(value.trim()); }
        catch (RuntimeException invalid) { throw error("INVALID_DATE", "Date must use ISO-8601 format"); }
    }

    private static String enumValue(String value, String allowed, String code) {
        var normalized = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches(allowed)) throw error(code, "Unsupported profile subtype");
        return normalized;
    }

    private static String reason(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.length() < 8 || normalized.length() > 500) throw error("INVALID_REASON", "Reason must contain 8 to 500 characters");
        return normalized;
    }

    private static String key(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty() || normalized.length() > 160) throw error("INVALID_IDEMPOTENCY_KEY", "Idempotency key is required");
        return normalized;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String nullToEmpty(Object value) { return value == null ? "" : value.toString(); }

    private static GraphqlErrorException error(String code, String message) {
        var classification = switch (code) {
            case "PROFILE_NOT_FOUND" -> ErrorType.NOT_FOUND;
            case "UNAUTHENTICATED" -> ErrorType.UNAUTHORIZED;
            default -> ErrorType.BAD_REQUEST;
        };
        return GraphqlErrorException.newErrorException().message(message)
            .errorClassification(classification).extensions(Map.of("code", code)).build();
    }

    public record CustomerDraft(String fullName, String email, String contactPhone,
                                String dateOfBirth, String address, String reason,
                                String idempotencyKey) {}
    public record AdminDraft(String fullName, String email, String contactPhone,
                             String employeeCode, String subtype, String hiredOn,
                             String reason, String idempotencyKey) {}
    public record HostDraft(String fullName, String email, String contactPhone,
                            String hostCode, String address, String taxCode,
                            String reason, String idempotencyKey) {}
    public record ProfileView(UUID profileId, UUID accountId, String accountType,
                              String displayName, String email, String contactPhone,
                              String status, String referenceCode, String subtype,
                              String verificationStatus, LocalDate relevantDate,
                              String address, String taxCode, long version,
                              OffsetDateTime createdAt, OffsetDateTime updatedAt) {}

    private record NormalizedDraft(String accountType, String fullName, String email,
                                   String phone, String referenceCode, String subtype,
                                   String verificationStatus, LocalDate relevantDate,
                                   String address, String taxCode, String reason,
                                   String idempotencyKey) {}
    private record CreationRequest(String requestHash, String profileType, UUID profileId) {}
}
