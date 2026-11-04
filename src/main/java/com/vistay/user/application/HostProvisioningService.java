package com.vistay.user.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Projects Authentication-owned HOST lifecycle events into User-owned profile
 * and authorization rows.  The service deliberately keeps the event boundary
 * small: it never reads Authentication or Property storage and never creates a
 * property ownership binding.
 */
@Service
public class HostProvisioningService {
    public static final String ACCOUNT_PROVISIONED = "vistay.auth.account-provisioned";
    public static final String HOST_IDENTITY_ACTIVATED = "vistay.host.identity-activated";
    public static final String HOST_LIFECYCLE_CHANGED = "vistay.host.lifecycle-changed";
    public static final String HOST_PROFILE_PROVISIONED = "vistay.host.profile-provisioned";
    public static final String AUTHORIZATION_CHANGED = "vistay.user.authorization-changed";

    private static final String CONSUMER_NAME = "user-host-provisioning-v1";
    private static final String HOST = "HOST";
    private static final String HOST_ROLE = "HOST_PARTNER";

    private final JdbcClient jdbc;
    private final ObjectMapper json;
    private final TransactionTemplate transactions;

    public HostProvisioningService(
        JdbcClient jdbc,
        ObjectMapper json,
        TransactionTemplate transactions
    ) {
        this.jdbc = jdbc;
        this.json = json;
        this.transactions = transactions;
    }

    /**
     * Consumes one validated v1 event.  Claiming the event and all projection
     * writes happen in the same transaction, so a failed policy or collision
     * leaves no processed-event tombstone or partial profile behind.
     */
    public void consume(EventEnvelope event) {
        validateEnvelope(event);
        var businessKey = businessKey(event);
        var fingerprint = fingerprint(event);
        transactions.executeWithoutResult(status -> {
            if (!claim(event, businessKey, fingerprint)) {
                return;
            }
            switch (event.type()) {
                case ACCOUNT_PROVISIONED -> provisionHost(hostAccount(event));
                case HOST_IDENTITY_ACTIVATED -> activateHost(event);
                case HOST_LIFECYCLE_CHANGED -> projectLifecycle(event);
                default -> throw failure("HOST_UNSUPPORTED_EVENT", "Unsupported HOST event");
            }
        });
    }

    private void provisionHost(HostAccount account) {
        rejectOwnershipClaims(account.data());
        ensureHostRealm(account.data());
        ensureNoCrossTypeProfile(account.accountId());

        var subjectResult = lockOrCreateSubject(account.accountId());
        var subject = subjectResult.row();
        var profile = lockOrCreateProfile(account, subject.id());
        var assignment = ensureHostPartner(subject.id());

        if (subjectResult.created() || profile.created() || profile.repaired() || assignment.created()) {
            audit(
                subject.id(),
                "HOST_PROFILE_PROVISIONED",
                Map.of(),
                Map.of(
                    "accountType", HOST,
                    "profileId", profile.id().toString(),
                    "authorizationVersion", subject.authorizationVersion(),
                    "profileStatus", profile.profileStatus(),
                    "roleCode", HOST_ROLE
                ),
                account.event().correlationId()
            );
            emitProfileProvisioned(account, subject, profile.row());
        }
    }

    private void activateHost(EventEnvelope event) {
        var data = event.data();
        ensureHostRealm(data);
        requireValue(data, "subjectType", HOST);
        requireValue(data, "state", "ACTIVE");
        requireValue(data, "activationSource", "KEYCLOAK");
        var accountId = requiredUuid(data, "accountId");
        var authorizationVersion = requiredLong(data, "authorizationVersion");
        requireAggregateVersion(event, data);

        var subject = findSubject(accountId);
        var profile = findProfile(accountId);
        if (subject == null || profile == null) {
            // A future producer may carry the approved PROFILE_CORE fields on
            // activation.  Accept that form, but never synthesize a name or
            // ownership from an account ID when it does not.
            var displayName = optionalText(data, "displayName");
            if (displayName == null) {
                throw failure("HOST_PROFILE_NOT_PROVISIONED", "HOST profile must be provisioned before activation");
            }
            ensureNoCrossTypeProfile(accountId);
            var account = new HostAccount(
                event,
                accountId,
                displayName,
                optionalText(data, "email"),
                optionalUuid(data, "profileId"),
                optionalText(data, "verificationStatus"),
                optionalText(data, "preferredLocale"),
                data
            );
            provisionHost(account);
            subject = findSubject(accountId);
            profile = findProfile(accountId);
        }
        if (subject == null || profile == null) {
            throw failure("HOST_PROFILE_NOT_PROVISIONED", "HOST profile was not created");
        }
        applyState(
            event,
            subject,
            profile,
            "ACTIVE",
            authorizationVersion,
            "HOST_IDENTITY_ACTIVATED"
        );
    }

    private void projectLifecycle(EventEnvelope event) {
        var data = event.data();
        ensureHostRealm(data);
        requireValue(data, "subjectType", HOST);
        var accountId = requiredUuid(data, "accountId");
        var previousState = requiredText(data, "previousState");
        var state = requiredText(data, "state");
        var authorizationVersion = requiredLong(data, "authorizationVersion");
        requireAggregateVersion(event, data);
        if (!List.of("ACTIVE", "SUSPENDED", "DEACTIVATED").contains(state)
            || !List.of("INVITED", "ACTIVE", "SUSPENDED").contains(previousState)) {
            throw failure("HOST_INVALID_STATE_TRANSITION", "Unsupported HOST lifecycle state");
        }

        var subject = findSubject(accountId);
        var profile = findProfile(accountId);
        if (subject == null || profile == null) {
            throw failure("HOST_PROFILE_NOT_PROVISIONED", "HOST profile was not provisioned");
        }
        var currentState = externalState(subject, profile);
        if (!currentState.equals(previousState) && !currentState.equals(state)) {
            throw failure("HOST_INVALID_STATE_TRANSITION", "HOST lifecycle predecessor does not match User state");
        }
        applyState(event, subject, profile, state, authorizationVersion, "HOST_LIFECYCLE_CHANGED");
    }

    private void applyState(
        EventEnvelope event,
        SubjectRow subject,
        ProfileRow profile,
        String targetState,
        long requestedAuthorizationVersion,
        String auditAction
    ) {
        if (requestedAuthorizationVersion < subject.authorizationVersion()) {
            throw failure("HOST_STALE_VERSION", "HOST authorization version is stale");
        }
        var targetProfileStatus = profileStatus(targetState);
        var targetActive = "ACTIVE".equals(targetState);
        var effectiveChange = !targetProfileStatus.equals(profile.profileStatus())
            || subject.active() != targetActive;
        if (!effectiveChange) {
            if (requestedAuthorizationVersion != subject.authorizationVersion()) {
                throw failure("HOST_INVALID_STATE_TRANSITION", "HOST state did not change with the supplied authorization version");
            }
            return;
        }

        var before = Map.of(
            "profileStatus", profile.profileStatus(),
            "active", subject.active(),
            "authorizationVersion", subject.authorizationVersion()
        );
        var nextProfileVersion = jdbc.sql("""
            UPDATE hosts
            SET profile_status = :profileStatus,
                version = version + 1,
                updated_at = now()
            WHERE id = :profileId AND version = :expectedVersion
            RETURNING version
            """)
            .param("profileStatus", targetProfileStatus)
            .param("profileId", profile.id())
            .param("expectedVersion", profile.version())
            .query(Long.class)
            .optional()
            .orElseThrow(() -> failure("HOST_VERSION_CONFLICT", "HOST profile changed concurrently"));

        var nextAuthorizationVersion = jdbc.sql("""
            UPDATE authorization_subjects
            SET active = :active,
                authorization_version = :authorizationVersion,
                updated_at = now()
            WHERE id = :subjectId AND authorization_version <= :authorizationVersion
            RETURNING authorization_version
            """)
            .param("active", targetActive)
            .param("authorizationVersion", requestedAuthorizationVersion)
            .param("subjectId", subject.id())
            .query(Long.class)
            .optional()
            .orElseThrow(() -> failure("HOST_STALE_VERSION", "HOST authorization version changed concurrently"));

        var after = Map.of(
            "profileStatus", targetProfileStatus,
            "active", targetActive,
            "authorizationVersion", nextAuthorizationVersion
        );
        audit(subject.id(), auditAction, before, after, event.correlationId());
        emitAuthorizationChanged(event, subject.id(), subject.authAccountId(),
            nextAuthorizationVersion, targetState);
    }

    private SubjectResult lockOrCreateSubject(UUID accountId) {
        var existing = findSubject(accountId);
        if (existing != null) {
            if (!HOST.equals(existing.accountType())) {
                throw failure("HOST_SUBJECT_COLLISION", "Authorization subject belongs to another account type");
            }
            return new SubjectResult(existing, false);
        }

        var inserted = jdbc.sql("""
            INSERT INTO authorization_subjects(account_type, auth_account_id, active)
            VALUES ('HOST', :accountId, false)
            ON CONFLICT DO NOTHING
            RETURNING id, account_type, auth_account_id, active, authorization_version
            """)
            .param("accountId", accountId)
            .query(SubjectRow.class)
            .optional()
            .orElse(null);
        if (inserted != null) {
            return new SubjectResult(inserted, true);
        }

        var concurrent = findSubject(accountId);
        if (concurrent == null) {
            throw failure("HOST_SUBJECT_COLLISION", "HOST authorization subject could not be claimed");
        }
        if (!HOST.equals(concurrent.accountType())) {
            throw failure("HOST_SUBJECT_COLLISION", "Authorization subject belongs to another account type");
        }
        return new SubjectResult(concurrent, false);
    }

    private SubjectRow findSubject(UUID accountId) {
        return jdbc.sql("""
            SELECT id, account_type, auth_account_id, active, authorization_version
            FROM authorization_subjects
            WHERE auth_account_id = :accountId
            FOR UPDATE
            """)
            .param("accountId", accountId)
            .query(SubjectRow.class)
            .optional()
            .orElse(null);
    }

    private ProfileResult lockOrCreateProfile(HostAccount account, UUID subjectId) {
        var existing = findProfile(account.accountId());
        if (existing != null) {
            if (account.profileId() != null && !account.profileId().equals(existing.id())) {
                throw failure("HOST_SUBJECT_COLLISION", "HOST profile ID does not match the existing account lineage");
            }
            if (!account.displayName().equals(existing.fullName())
                || (account.email() != null && !account.email().equals(existing.email()))
                || !account.verificationStatus().equals(existing.verificationStatus())) {
                throw failure("HOST_IDEMPOTENCY_CONFLICT", "HOST profile canonical fields do not agree");
            }
            var repaired = false;
            if (existing.authorizationSubjectId() == null) {
                jdbc.sql("""
                    UPDATE hosts SET authorization_subject_id = :subjectId, updated_at = now()
                    WHERE id = :profileId
                    """)
                    .param("subjectId", subjectId)
                    .param("profileId", existing.id())
                    .update();
                repaired = true;
            } else if (!subjectId.equals(existing.authorizationSubjectId())) {
                throw failure("HOST_SUBJECT_COLLISION", "HOST profile is linked to another authorization subject");
            }
            return new ProfileResult(existing, false, repaired);
        }

        var inserted = account.profileId() == null
            ? jdbc.sql("""
                INSERT INTO hosts(
                    auth_account_id, authorization_subject_id, full_name, email,
                    profile_status, verification_status, version
                ) VALUES (
                    :accountId, :subjectId, :fullName, :email,
                    'INACTIVE', :verificationStatus, 1
                )
                ON CONFLICT DO NOTHING
                RETURNING id, auth_account_id, authorization_subject_id, full_name,
                          email::text AS email, profile_status, verification_status, version
                """)
                .param("accountId", account.accountId())
                .param("subjectId", subjectId)
                .param("fullName", account.displayName())
                .param("email", account.email())
                .param("verificationStatus", account.verificationStatus())
                .query(ProfileRow.class)
                .optional()
                .orElse(null)
            : jdbc.sql("""
                INSERT INTO hosts(
                    id, auth_account_id, authorization_subject_id, full_name, email,
                    profile_status, verification_status, version
                ) VALUES (
                    :profileId, :accountId, :subjectId, :fullName, :email,
                    'INACTIVE', :verificationStatus, 1
                )
                ON CONFLICT DO NOTHING
                RETURNING id, auth_account_id, authorization_subject_id, full_name,
                          email::text AS email, profile_status, verification_status, version
                """)
                .param("profileId", account.profileId())
                .param("accountId", account.accountId())
                .param("subjectId", subjectId)
                .param("fullName", account.displayName())
                .param("email", account.email())
                .param("verificationStatus", account.verificationStatus())
                .query(ProfileRow.class)
                .optional()
                .orElse(null);
        if (inserted != null) {
            return new ProfileResult(inserted, true, false);
        }

        var concurrent = findProfile(account.accountId());
        if (concurrent == null) {
            throw failure("HOST_SUBJECT_COLLISION", "HOST profile could not be claimed");
        }
        if (account.profileId() != null && !account.profileId().equals(concurrent.id())) {
            throw failure("HOST_SUBJECT_COLLISION", "HOST profile ID does not match the existing account lineage");
        }
        if (!account.displayName().equals(concurrent.fullName())
            || (account.email() != null && !account.email().equals(concurrent.email()))
            || !account.verificationStatus().equals(concurrent.verificationStatus())) {
            throw failure("HOST_IDEMPOTENCY_CONFLICT", "HOST profile canonical fields do not agree");
        }
        return new ProfileResult(concurrent, false, false);
    }

    private ProfileRow findProfile(UUID accountId) {
        return jdbc.sql("""
            SELECT id, auth_account_id, authorization_subject_id, full_name,
                   email::text AS email, profile_status, verification_status, version
            FROM hosts
            WHERE auth_account_id = :accountId
            FOR UPDATE
            """)
            .param("accountId", accountId)
            .query(ProfileRow.class)
            .optional()
            .orElse(null);
    }

    private void ensureNoCrossTypeProfile(UUID accountId) {
        var collision = jdbc.sql("""
            SELECT EXISTS (SELECT 1 FROM customers WHERE auth_account_id = :accountId)
                OR EXISTS (SELECT 1 FROM admin_users WHERE auth_account_id = :accountId)
            """)
            .param("accountId", accountId)
            .query(Boolean.class)
            .single();
        if (collision) {
            throw failure("HOST_SUBJECT_COLLISION", "HOST account is already projected as another profile type");
        }
    }

    private AssignmentResult ensureHostPartner(UUID subjectId) {
        var roleId = jdbc.sql("""
            SELECT id FROM roles
            WHERE code = 'HOST_PARTNER' AND audience = 'HOST' AND active
            """)
            .query(UUID.class)
            .optional()
            .orElseThrow(() -> failure("HOST_AUTHORIZATION_POLICY_INVALID", "HOST_PARTNER policy is unavailable"));

        var policy = jdbc.sql("""
            SELECT count(DISTINCT rp.permission_id) AS permission_count,
                   count(*) FILTER (WHERE rpp.default_scope) AS default_count,
                   count(*) FILTER (
                       WHERE rpp.default_scope AND rpp.scope_type NOT IN ('SELF', 'OWN')
                   ) AS invalid_default_count
            FROM role_permissions rp
            LEFT JOIN role_permission_policies rpp
              ON rpp.role_id = rp.role_id AND rpp.permission_id = rp.permission_id
            WHERE rp.role_id = :roleId
            """)
            .param("roleId", roleId)
            .query(PolicyRow.class)
            .single();
        if (policy.permissionCount() == 0
            || policy.defaultCount() != policy.permissionCount()
            || policy.invalidDefaultCount() != 0) {
            throw failure("HOST_AUTHORIZATION_POLICY_INVALID", "HOST_PARTNER must default every permission to SELF or OWN");
        }

        var assignment = jdbc.sql("""
            INSERT INTO subject_role_assignments(subject_id, role_id)
            VALUES (:subjectId, :roleId)
            ON CONFLICT (subject_id, role_id) WHERE revoked_at IS NULL DO NOTHING
            RETURNING id
            """)
            .param("subjectId", subjectId)
            .param("roleId", roleId)
            .query(UUID.class)
            .optional()
            .orElse(null);
        var assignmentId = assignment == null
            ? jdbc.sql("""
                SELECT id FROM subject_role_assignments
                WHERE subject_id = :subjectId AND role_id = :roleId AND revoked_at IS NULL
                FOR UPDATE
                """)
                .param("subjectId", subjectId)
                .param("roleId", roleId)
                .query(UUID.class)
                .optional()
                .orElseThrow(() -> failure("HOST_AUTHORIZATION_POLICY_INVALID", "HOST_PARTNER assignment could not be claimed"))
            : assignment;

        jdbc.sql("""
            INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
            SELECT :assignmentId, rp.permission_id, rpp.scope_type
            FROM role_permissions rp
            JOIN role_permission_policies rpp
              ON rpp.role_id = rp.role_id
             AND rpp.permission_id = rp.permission_id
             AND rpp.default_scope
             AND rpp.scope_type IN ('SELF', 'OWN')
            WHERE rp.role_id = :roleId
            ON CONFLICT DO NOTHING
            """)
            .param("assignmentId", assignmentId)
            .param("roleId", roleId)
            .update();

        var scopes = jdbc.sql("""
            SELECT count(*) AS scope_count,
                   count(*) FILTER (WHERE srps.scope_type NOT IN ('SELF', 'OWN')) AS invalid_scope_count
            FROM subject_role_permission_scopes srps
            JOIN role_permissions rp ON rp.permission_id = srps.permission_id
            WHERE srps.assignment_id = :assignmentId AND rp.role_id = :roleId
            """)
            .param("assignmentId", assignmentId)
            .param("roleId", roleId)
            .query(ScopeCount.class)
            .single();
        if (scopes.scopeCount() != policy.permissionCount() || scopes.invalidScopeCount() != 0) {
            throw failure("HOST_AUTHORIZATION_POLICY_INVALID", "HOST_PARTNER assignment is not least privilege");
        }
        return new AssignmentResult(assignment != null);
    }

    private void audit(
        UUID subjectId,
        String action,
        Map<String, ?> before,
        Map<String, ?> after,
        String correlationId
    ) {
        jdbc.sql("""
            INSERT INTO authorization_audit_events(
                actor_subject_id, target_subject_id, action,
                before_state, after_state, reason, correlation_id
            ) VALUES (
                NULL, :subjectId, :action,
                CAST(:beforeState AS jsonb), CAST(:afterState AS jsonb),
                :reason, :correlationId
            )
            """)
            .param("subjectId", subjectId)
            .param("action", action)
            .param("beforeState", writeJson(before))
            .param("afterState", writeJson(after))
            .param("reason", "Trusted HOST lifecycle projection")
            .param("correlationId", correlationId)
            .update();
    }

    private void emitProfileProvisioned(HostAccount account, SubjectRow subject, ProfileRow profile) {
        var verificationStatus = switch (profile.verificationStatus()) {
            case "VERIFIED" -> "VERIFIED";
            case "PENDING" -> "PENDING";
            default -> "PENDING";
        };
        var payload = Map.of(
            "profileId", profile.id().toString(),
            "accountId", profile.authAccountId().toString(),
            "realm", HOST,
            "subjectType", HOST,
            "displayName", profile.fullName(),
            "preferredLocale", account.preferredLocale(),
            "verificationStatus", verificationStatus,
            "aggregateVersion", profile.version(),
            "provisionedAt", OffsetDateTime.now(ZoneOffset.UTC).toString()
        );
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id, causation_id
            ) VALUES (
                'HostProfile', :profileId, :aggregateVersion, :eventType,
                1, CAST(:payload AS jsonb), :correlationId, :causationId
            )
            """)
            .param("profileId", profile.id())
            .param("aggregateVersion", profile.version())
            .param("eventType", HOST_PROFILE_PROVISIONED)
            .param("payload", writeJson(payload))
            .param("correlationId", account.event().correlationId())
            .param("causationId", account.event().eventId().toString())
            .update();
    }

    private void emitAuthorizationChanged(
        EventEnvelope event,
        UUID subjectId,
        UUID accountId,
        long authorizationVersion,
        String state
    ) {
        var payload = Map.of(
            "accountId", accountId.toString(),
            "accountType", HOST,
            "authorizationVersion", authorizationVersion,
            "state", state,
            "changedAt", OffsetDateTime.now(ZoneOffset.UTC).toString()
        );
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id, causation_id
            ) VALUES (
                'AuthorizationSubject', :subjectId, :aggregateVersion, :eventType,
                1, CAST(:payload AS jsonb), :correlationId, :causationId
            )
            """)
            .param("subjectId", subjectId)
            .param("aggregateVersion", authorizationVersion)
            .param("eventType", AUTHORIZATION_CHANGED)
            .param("payload", writeJson(payload))
            .param("correlationId", event.correlationId())
            .param("causationId", event.eventId().toString())
            .update();
    }

    private boolean claim(EventEnvelope event, String businessKey, String payloadHash) {
        var inserted = jdbc.sql("""
            INSERT INTO processed_events(
                event_id, consumer_name, payload_hash, business_key, event_type
            ) VALUES (:eventId, :consumerName, :payloadHash, :businessKey, :eventType)
            ON CONFLICT DO NOTHING
            """)
            .param("eventId", event.eventId())
            .param("consumerName", CONSUMER_NAME)
            .param("payloadHash", payloadHash)
            .param("businessKey", businessKey)
            .param("eventType", event.type())
            .update();
        if (inserted == 1) {
            return true;
        }

        var byEvent = jdbc.sql("""
            SELECT event_id, payload_hash, business_key, event_type
            FROM processed_events
            WHERE event_id = :eventId AND consumer_name = :consumerName
            FOR UPDATE
            """)
            .param("eventId", event.eventId())
            .param("consumerName", CONSUMER_NAME)
            .query(ProcessedEventRow.class)
            .optional()
            .orElse(null);
        if (byEvent != null) {
            verifyReplay(byEvent, payloadHash, "HOST_EVENT_ID_COLLISION");
            return false;
        }

        var byBusinessKey = jdbc.sql("""
            SELECT event_id, payload_hash, business_key, event_type
            FROM processed_events
            WHERE consumer_name = :consumerName AND business_key = :businessKey
            FOR UPDATE
            """)
            .param("consumerName", CONSUMER_NAME)
            .param("businessKey", businessKey)
            .query(ProcessedEventRow.class)
            .optional()
            .orElseThrow(() -> failure("HOST_INBOX_CONFLICT", "HOST event could not claim its deduplication key"));
        verifyReplay(byBusinessKey, payloadHash, "HOST_EVENT_BUSINESS_CONFLICT");
        return false;
    }

    private static void verifyReplay(ProcessedEventRow existing, String payloadHash, String code) {
        if (existing.payloadHash() == null
            || !existing.payloadHash().trim().equals(payloadHash)) {
            throw failure(code, "HOST event replay does not match the canonical payload");
        }
    }

    private String businessKey(EventEnvelope event) {
        var accountId = requiredUuid(event.data(), "accountId");
        return switch (event.type()) {
            case ACCOUNT_PROVISIONED -> "HOST:PROVISION:" + accountId;
            case HOST_IDENTITY_ACTIVATED -> "HOST:ACTIVATION:" + accountId + ":" + event.aggregateVersion();
            case HOST_LIFECYCLE_CHANGED -> "HOST:LIFECYCLE:" + accountId + ":" + event.aggregateVersion();
            default -> throw failure("HOST_UNSUPPORTED_EVENT", "Unsupported HOST event");
        };
    }

    private String fingerprint(EventEnvelope event) {
        var canonical = String.join(
            "\n",
            event.type(),
            Integer.toString(event.version()),
            event.aggregateId() == null ? "" : event.aggregateId().toString(),
            Long.toString(event.aggregateVersion()),
            event.data().toString()
        );
        return sha256(canonical);
    }

    private HostAccount hostAccount(EventEnvelope event) {
        var data = event.data();
        var accountType = optionalText(data, "accountType");
        var realm = requiredText(data, "realm");
        if (accountType != null && !HOST.equals(accountType)) {
            throw failure("HOST_WRONG_REALM_OR_TYPE", "HOST consumer received a non-HOST account");
        }
        if (!HOST.equals(realm) && !"vistay-host".equals(realm)) {
            throw failure("HOST_WRONG_REALM_OR_TYPE", "HOST account must use the HOST realm");
        }
        var accountId = requiredUuid(data, "accountId");
        var displayName = requiredText(data, "displayName").trim();
        if (displayName.length() > 180) {
            throw failure("HOST_INVALID_EVENT", "HOST display name exceeds the profile limit");
        }
        var email = requiredText(data, "email").trim().toLowerCase(Locale.ROOT);
        if (email.length() > 320) {
            throw failure("HOST_INVALID_EVENT", "HOST email exceeds the profile limit");
        }
        var verification = normalizeVerification(optionalText(data, "verificationStatus"));
        return new HostAccount(
            event,
            accountId,
            displayName,
            email,
            optionalUuid(data, "profileId"),
            verification,
            optionalText(data, "preferredLocale"),
            data
        );
    }

    private void validateEnvelope(EventEnvelope event) {
        if (event == null || event.eventId() == null || event.type() == null
            || event.aggregateId() == null || event.aggregateVersion() < 1
            || event.correlationId() == null || event.occurredAt() == null
            || event.correlationId().isBlank() || event.data() == null || !event.data().isObject()) {
            throw failure("HOST_INVALID_EVENT", "HOST event envelope is incomplete");
        }
        if (event.version() != 1) {
            throw failure("HOST_UNSUPPORTED_EVENT_VERSION", "HOST event version is unsupported");
        }
        if (!List.of(ACCOUNT_PROVISIONED, HOST_IDENTITY_ACTIVATED, HOST_LIFECYCLE_CHANGED)
            .contains(event.type())) {
            throw failure("HOST_UNSUPPORTED_EVENT", "Unsupported HOST event");
        }
    }

    private static void requireAggregateVersion(EventEnvelope event, JsonNode data) {
        var dataVersion = requiredLong(data, "aggregateVersion");
        if (dataVersion != event.aggregateVersion()) {
            throw failure("HOST_INVALID_EVENT", "HOST aggregate version does not match the envelope");
        }
    }

    private static void ensureHostRealm(JsonNode data) {
        var realm = requiredText(data, "realm");
        if (!HOST.equals(realm) && !"vistay-host".equals(realm)) {
            throw failure("HOST_WRONG_REALM_OR_TYPE", "HOST event must use the HOST realm");
        }
    }

    private static void requireValue(JsonNode data, String field, String expected) {
        if (!expected.equals(requiredText(data, field))) {
            throw failure("HOST_WRONG_REALM_OR_TYPE", "HOST event has an invalid " + field);
        }
    }

    private static void rejectOwnershipClaims(JsonNode data) {
        for (var field : List.of("propertyId", "propertyIds", "branchId", "ownershipTerm", "propertyOwnership")) {
            if (data.get(field) != null && !data.get(field).isNull()) {
                throw failure("HOST_OWNERSHIP_CLAIM_FORBIDDEN", "HOST provisioning cannot claim Property ownership");
            }
        }
    }

    private static String profileStatus(String state) {
        return switch (state) {
            case "ACTIVE" -> "ACTIVE";
            case "SUSPENDED" -> "SUSPENDED";
            case "DEACTIVATED", "INVITED" -> "INACTIVE";
            default -> throw failure("HOST_INVALID_STATE_TRANSITION", "Unsupported HOST state");
        };
    }

    private static String externalState(SubjectRow subject, ProfileRow profile) {
        if ("ACTIVE".equals(profile.profileStatus()) && subject.active()) {
            return "ACTIVE";
        }
        if ("SUSPENDED".equals(profile.profileStatus())) {
            return "SUSPENDED";
        }
        return "INVITED";
    }

    private static String normalizeVerification(String value) {
        if (value == null || value.isBlank()) {
            return "UNVERIFIED";
        }
        return switch (value) {
            case "UNVERIFIED", "PENDING", "VERIFIED" -> value;
            case "REQUIRES_REVIEW" -> "PENDING";
            default -> throw failure("HOST_INVALID_EVENT", "Unsupported HOST verification state");
        };
    }

    private static String requiredText(JsonNode data, String field) {
        var node = data.get(field);
        if (node == null || node.isNull() || node.asString() == null || node.asString().isBlank()) {
            throw failure("HOST_INVALID_EVENT", "Missing HOST event field: " + field);
        }
        return node.asString();
    }

    private static String optionalText(JsonNode data, String field) {
        var node = data.get(field);
        if (node == null || node.isNull() || node.asString() == null || node.asString().isBlank()) {
            return null;
        }
        return node.asString();
    }

    private static UUID requiredUuid(JsonNode data, String field) {
        try {
            return UUID.fromString(requiredText(data, field));
        } catch (IllegalArgumentException invalid) {
            throw failure("HOST_INVALID_EVENT", "Invalid HOST UUID field: " + field);
        }
    }

    private static UUID optionalUuid(JsonNode data, String field) {
        var value = optionalText(data, field);
        if (value == null) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException invalid) {
            throw failure("HOST_INVALID_EVENT", "Invalid HOST UUID field: " + field);
        }
    }

    private static long requiredLong(JsonNode data, String field) {
        try {
            var value = Long.parseLong(requiredText(data, field));
            if (value < 1) {
                throw new NumberFormatException();
            }
            return value;
        } catch (NumberFormatException invalid) {
            throw failure("HOST_INVALID_EVENT", "Invalid HOST version field: " + field);
        }
    }

    private String writeJson(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JacksonException failure) {
            throw new IllegalStateException("Cannot serialize HOST projection evidence", failure);
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static HostProvisioningException failure(String code, String message) {
        return new HostProvisioningException(code, message);
    }

    public record EventEnvelope(
        UUID eventId,
        String type,
        int version,
        UUID aggregateId,
        long aggregateVersion,
        String correlationId,
        String causationId,
        OffsetDateTime occurredAt,
        JsonNode data
    ) {}

    public static final class HostProvisioningException extends IllegalStateException {
        private final String code;

        public HostProvisioningException(String code, String message) {
            super(code + ": " + message);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    private record HostAccount(
        EventEnvelope event,
        UUID accountId,
        String displayName,
        String email,
        UUID profileId,
        String verificationStatus,
        String preferredLocale,
        JsonNode data
    ) {
        private HostAccount {
            verificationStatus = normalizeVerification(verificationStatus);
            if (preferredLocale == null || preferredLocale.isBlank()) {
                preferredLocale = "vi-VN";
            } else if (!preferredLocale.matches("^[a-z]{2}(?:-[A-Z]{2})?$")) {
                throw failure("HOST_INVALID_EVENT", "Invalid HOST preferred locale");
            }
        }
    }

    private record SubjectRow(
        UUID id,
        String accountType,
        UUID authAccountId,
        boolean active,
        long authorizationVersion
    ) {}

    private record SubjectResult(SubjectRow row, boolean created) {}

    private record ProfileRow(
        UUID id,
        UUID authAccountId,
        UUID authorizationSubjectId,
        String fullName,
        String email,
        String profileStatus,
        String verificationStatus,
        long version
    ) {}

    private record ProfileResult(ProfileRow row, boolean created, boolean repaired) {
        UUID id() { return row.id(); }
        String profileStatus() { return row.profileStatus(); }
        long version() { return row.version(); }
        UUID authAccountId() { return row.authAccountId(); }
        String fullName() { return row.fullName(); }
        String verificationStatus() { return row.verificationStatus(); }
    }

    private record AssignmentResult(boolean created) {}
    private record PolicyRow(long permissionCount, long defaultCount, long invalidDefaultCount) {}
    private record ScopeCount(long scopeCount, long invalidScopeCount) {}
    private record ProcessedEventRow(UUID eventId, String payloadHash, String businessKey, String eventType) {}
}
