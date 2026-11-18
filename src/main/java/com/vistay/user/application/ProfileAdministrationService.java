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
    private final IdentityProtection identityProtection;

    public ProfileAdministrationService(
        JdbcClient jdbc,
        TransactionTemplate transactions,
        ObjectMapper json,
        IdentityProtection identityProtection
    ) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.json = json;
        this.identityProtection = identityProtection;
    }

    public ProfileView createCustomer(UUID actorAccountId, CustomerDraft draft) {
        var normalizedEmail = email(draft.email());
        var normalizedPhone = phone(draft.contactPhone());
        if (normalizedEmail == null && normalizedPhone == null) {
            throw error("CUSTOMER_CONTACT_REQUIRED", "Customer email or phone number is required");
        }
        var nationality = nationality(draft.nationalityCode());
        var documentType = documentType(draft.documentType(), nationality.alpha2());
        var documentNumber = documentNumber(documentType, draft.documentNumber());
        var protectedDocument = protectDocument(nationality.alpha2(), documentType, documentNumber);
        var normalized = new NormalizedDraft(
            "CUSTOMER", name(draft.fullName()), normalizedEmail, normalizedPhone,
            null, null, null, date(draft.dateOfBirth()), text(draft.address(), 500), null,
            nationality.alpha3(), nationality.alpha2(), documentType, protectedDocument,
            reason(draft.reason()), key(draft.idempotencyKey())
        );
        return create(actorAccountId, normalized);
    }

    public IdentityDocumentAvailability customerIdentityDocumentAvailability(
        String nationalityCode,
        String requestedDocumentType,
        String requestedDocumentNumber
    ) {
        var nationality = nationality(nationalityCode);
        var documentType = documentType(requestedDocumentType, nationality.alpha2());
        var documentNumber = documentNumber(documentType, requestedDocumentNumber);
        var lookup = hashDocument(nationality.alpha2(), documentType, documentNumber);
        var available = !identityDocumentExists(
            "CUSTOMER", nationality.alpha2(), documentType, lookup.value()
        );
        return new IdentityDocumentAvailability(available);
    }

    public CustomerContactAvailability customerContactAvailability(
        String requestedEmail,
        String requestedPhone
    ) {
        var normalizedEmail = email(requestedEmail);
        var normalizedPhone = phone(requestedPhone);
        if (normalizedEmail == null && normalizedPhone == null) {
            throw error("CUSTOMER_CONTACT_REQUIRED", "Email or phone number is required for availability check");
        }
        return new CustomerContactAvailability(
            normalizedEmail == null ? null : !exists(
                "SELECT EXISTS(SELECT 1 FROM customers WHERE email = :value)", normalizedEmail
            ),
            normalizedPhone == null ? null : !exists(
                "SELECT EXISTS(SELECT 1 FROM customers WHERE normalized_phone = :value)", normalizedPhone
            )
        );
    }

    public ProfileView createAdmin(UUID actorAccountId, AdminDraft draft) {
        var subtype = enumValue(draft.subtype(), "STAFF|RECEPTIONIST|CTV|MANAGER|ADMIN", "INVALID_ADMIN_SUBTYPE");
        var normalized = new NormalizedDraft(
            "ADMIN", name(draft.fullName()), email(draft.email()), phone(draft.contactPhone()),
            code(draft.employeeCode()), subtype, null, date(draft.hiredOn()), null, null,
            null, null, null, null,
            reason(draft.reason()), key(draft.idempotencyKey())
        );
        return create(actorAccountId, normalized);
    }

    public ProfileView createHost(UUID actorAccountId, HostDraft draft) {
        var normalized = new NormalizedDraft(
            "HOST", name(draft.fullName()), email(draft.email()), phone(draft.contactPhone()),
            code(draft.hostCode()), null, "UNVERIFIED", null, text(draft.address(), 500),
            text(draft.taxCode(), 40), null, null, null, null,
            reason(draft.reason()), key(draft.idempotencyKey())
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
                       address, NULL::varchar AS tax_code, nationality_code,
                       (SELECT d.document_type FROM profile_identity_documents d
                        WHERE d.profile_type = 'CUSTOMER' AND d.profile_id = customers.id
                        ORDER BY d.created_at LIMIT 1) AS document_type,
                       version, created_at, updated_at
                FROM customers WHERE id = :id
                """).param("id", profileId).query(ProfileView.class).optional()
                .orElseThrow(() -> error("PROFILE_NOT_FOUND", "Customer profile was not found"));
            case "ADMIN" -> jdbc.sql("""
                SELECT id AS profile_id, auth_account_id AS account_id, 'ADMIN' AS account_type,
                       full_name AS display_name, email::text AS email, normalized_phone AS contact_phone,
                       profile_status AS status, employee_code AS reference_code, user_type AS subtype,
                       NULL::varchar AS verification_status, hired_on AS relevant_date,
                       NULL::varchar AS address, NULL::varchar AS tax_code,
                       NULL::char(3) AS nationality_code, NULL::varchar AS document_type,
                       version, created_at, updated_at
                FROM admin_users WHERE id = :id
                """).param("id", profileId).query(ProfileView.class).optional()
                .orElseThrow(() -> error("PROFILE_NOT_FOUND", "Admin profile was not found"));
            case "HOST" -> jdbc.sql("""
                SELECT id AS profile_id, auth_account_id AS account_id, 'HOST' AS account_type,
                       full_name AS display_name, email::text AS email, normalized_phone AS contact_phone,
                       profile_status AS status, host_code AS reference_code, NULL::varchar AS subtype,
                       verification_status, NULL::date AS relevant_date,
                       address, tax_code, NULL::char(3) AS nationality_code,
                       NULL::varchar AS document_type, version, created_at, updated_at
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
            nullToEmpty(draft.nationalityCode()), nullToEmpty(draft.documentCountry()),
            nullToEmpty(draft.documentType()),
            draft.protectedDocument() == null ? "" : draft.protectedDocument().lookupHmac(),
            draft.reason()
        ));
        var replay = findRequest(draft.idempotencyKey());
        if (replay != null) return replay(replay, fingerprint, draft.accountType());

        try {
            var created = transactions.execute(status -> {
                ensureUnique(draft);
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
            throw constraintConflict(conflict);
        }
    }

    private void ensureUnique(NormalizedDraft draft) {
        var table = switch (draft.accountType()) {
            case "CUSTOMER" -> "customers";
            case "ADMIN" -> "admin_users";
            case "HOST" -> "hosts";
            default -> throw new IllegalStateException("Unsupported profile type");
        };
        if (draft.email() != null && exists(
            "SELECT EXISTS(SELECT 1 FROM " + table + " WHERE email = :value)", draft.email())) {
            throw error("PROFILE_EMAIL_ALREADY_EXISTS", "Email đã được dùng bởi một hồ sơ cùng loại");
        }
        if (draft.phone() != null && exists(
            "SELECT EXISTS(SELECT 1 FROM " + table + " WHERE normalized_phone = :value)", draft.phone())) {
            throw error("PROFILE_PHONE_ALREADY_EXISTS", "Số điện thoại đã được dùng bởi một hồ sơ cùng loại");
        }
        if (draft.protectedDocument() != null && identityDocumentExists(
            draft.accountType(), draft.documentCountry(), draft.documentType(),
            draft.protectedDocument().lookupHmac()
        )) {
            throw error("PROFILE_IDENTITY_DOCUMENT_ALREADY_EXISTS", "Giấy tờ đã được dùng bởi một hồ sơ cùng loại");
        }
    }

    private boolean identityDocumentExists(
        String profileType,
        String documentCountry,
        String documentType,
        String lookupHmac
    ) {
        return Boolean.TRUE.equals(jdbc.sql("""
            SELECT EXISTS(
                SELECT 1 FROM profile_identity_documents
                WHERE profile_type = :profileType
                  AND document_country = :documentCountry
                  AND document_type = :documentType
                  AND lookup_hmac = :lookupHmac
            )
            """).param("profileType", profileType)
            .param("documentCountry", documentCountry)
            .param("documentType", documentType)
            .param("lookupHmac", lookupHmac)
            .query(Boolean.class).single());
    }

    private boolean exists(String sql, String value) {
        return Boolean.TRUE.equals(jdbc.sql(sql).param("value", value).query(Boolean.class).single());
    }

    static GraphqlErrorException constraintConflict(DataIntegrityViolationException conflict) {
        var details = exceptionDetails(conflict).toLowerCase(Locale.ROOT);
        if (details.contains("ux_profile_contact_email") || details.contains("ux_customer_email")
            || details.contains("ux_admin_email") || details.contains("ux_host_email")) {
            return error("PROFILE_EMAIL_ALREADY_EXISTS", "Email đã được dùng bởi một hồ sơ cùng loại");
        }
        if (details.contains("ux_profile_contact_phone") || details.contains("ux_customer_phone")
            || details.contains("ux_admin_phone") || details.contains("ux_host_phone")) {
            return error("PROFILE_PHONE_ALREADY_EXISTS", "Số điện thoại đã được dùng bởi một hồ sơ cùng loại");
        }
        if (details.contains("profile_identity_documents") && details.contains("lookup_hmac")) {
            return error("PROFILE_IDENTITY_DOCUMENT_ALREADY_EXISTS", "Giấy tờ đã được dùng bởi một hồ sơ cùng loại");
        }
        return error("PROFILE_CONFLICT", "Email, số điện thoại, mã hồ sơ hoặc giấy tờ đã tồn tại trong cùng loại hồ sơ");
    }

    private static String exceptionDetails(Throwable failure) {
        var details = new StringBuilder();
        for (var current = failure; current != null; current = current.getCause()) {
            if (current.getMessage() != null) details.append(' ').append(current.getMessage());
        }
        return details.toString();
    }

    private UUID insertProfile(NormalizedDraft draft) {
        return switch (draft.accountType()) {
            case "CUSTOMER" -> {
                var profileId = jdbc.sql("""
                    INSERT INTO customers(
                        full_name, email, normalized_phone, date_of_birth, nationality_code,
                        address, profile_status, version
                    ) VALUES (:name, :email, :phone, :date, :nationality, :address, 'ACTIVE', 1)
                    RETURNING id
                    """).param("name", draft.fullName()).param("email", draft.email())
                    .param("phone", draft.phone()).param("date", draft.relevantDate())
                    .param("nationality", draft.nationalityCode()).param("address", draft.address())
                    .query(UUID.class).single();
                var document = draft.protectedDocument();
                jdbc.sql("""
                    INSERT INTO profile_identity_documents(
                        profile_type, profile_id, document_country, document_type,
                        lookup_hmac, lookup_key_version, encrypted_value,
                        encryption_key_version, assurance_level
                    ) VALUES (
                        'CUSTOMER', :profileId, :documentCountry, :documentType,
                        :lookupHmac, :lookupVersion, :ciphertext,
                        :encryptionVersion, 'SELF_DECLARED'
                    )
                    """).param("profileId", profileId)
                    .param("documentCountry", draft.documentCountry())
                    .param("documentType", draft.documentType())
                    .param("lookupHmac", document.lookupHmac())
                    .param("lookupVersion", document.lookupKeyVersion())
                    .param("ciphertext", document.ciphertext())
                    .param("encryptionVersion", document.encryptionKeyVersion()).update();
                yield profileId;
            }
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

    private static Nationality nationality(String value) {
        var requested = value == null || value.isBlank() ? "VN" : value.trim().toUpperCase(Locale.ROOT);
        for (var alpha2 : Locale.getISOCountries()) {
            var locale = new Locale.Builder().setRegion(alpha2).build();
            var alpha3 = locale.getISO3Country();
            if (requested.equals(alpha2) || requested.equals(alpha3)) {
                return new Nationality(alpha2, alpha3);
            }
        }
        throw error("INVALID_NATIONALITY", "Nationality must use a valid ISO country code");
    }

    private static String documentType(String value, String nationalityAlpha2) {
        var normalized = value == null || value.isBlank()
            ? ("VN".equals(nationalityAlpha2) ? "CCCD" : "PASSPORT")
            : value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("CCCD|PASSPORT")) {
            throw error("INVALID_DOCUMENT_TYPE", "Unsupported identity document type");
        }
        if (!"VN".equals(nationalityAlpha2) && !"PASSPORT".equals(normalized)) {
            throw error("INVALID_DOCUMENT_TYPE", "Foreign customers must use a passport");
        }
        return normalized;
    }

    private static String documentNumber(String type, String value) {
        var normalized = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if ("CCCD".equals(type) && !normalized.matches("^[0-9]{12}$")) {
            throw error("INVALID_IDENTITY_DOCUMENT", "CCCD must contain exactly 12 digits");
        }
        if ("PASSPORT".equals(type) && !normalized.matches("^[A-Z0-9]{6,20}$")) {
            throw error("INVALID_IDENTITY_DOCUMENT", "Passport must contain 6 to 20 letters or digits");
        }
        return normalized;
    }

    private IdentityProtection.ProtectedDocument protectDocument(
        String country,
        String type,
        String number
    ) {
        try {
            return identityProtection.protectIdentityDocument(country, type, number);
        } catch (IllegalArgumentException invalid) {
            throw error("INVALID_IDENTITY_DOCUMENT", invalid.getMessage());
        } catch (RuntimeException unavailable) {
            throw error("IDENTITY_PROTECTION_UNAVAILABLE", "Identity document protection is unavailable");
        }
    }

    private IdentityProtection.ProtectedValue hashDocument(
        String country,
        String type,
        String number
    ) {
        try {
            return identityProtection.hmacIdentityDocument(country, type, number);
        } catch (IllegalArgumentException invalid) {
            throw error("INVALID_IDENTITY_DOCUMENT", invalid.getMessage());
        } catch (RuntimeException unavailable) {
            throw error("IDENTITY_PROTECTION_UNAVAILABLE", "Identity document protection is unavailable");
        }
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
        if (value == null || value.isBlank()) return "Tạo hồ sơ từ trang quản trị";
        var normalized = value.trim();
        if (normalized.length() > 500) throw error("INVALID_REASON", "Reason must not exceed 500 characters");
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
                                String dateOfBirth, String nationalityCode,
                                String documentType, String documentNumber,
                                String address, String reason, String idempotencyKey) {}
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
                              String address, String taxCode, String nationalityCode,
                              String documentType, long version,
                              OffsetDateTime createdAt, OffsetDateTime updatedAt) {}
    public record IdentityDocumentAvailability(boolean available) {}
    public record CustomerContactAvailability(Boolean emailAvailable, Boolean phoneAvailable) {}

    private record NormalizedDraft(String accountType, String fullName, String email,
                                   String phone, String referenceCode, String subtype,
                                   String verificationStatus, LocalDate relevantDate,
                                   String address, String taxCode, String nationalityCode,
                                   String documentCountry, String documentType,
                                   IdentityProtection.ProtectedDocument protectedDocument,
                                   String reason,
                                   String idempotencyKey) {}
    private record Nationality(String alpha2, String alpha3) {}
    private record CreationRequest(String requestHash, String profileType, UUID profileId) {}
}
