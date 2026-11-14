package com.vistay.user.application;

import com.vistay.user.application.AuthorizationSnapshotService.Scope;
import graphql.GraphqlErrorException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

@Service
public class ProfileIdentityLinkService {
    public static final String CHALLENGE_ISSUED = "vistay.user.profile-link-challenge-issued";
    public static final String PROFILE_LINKED = "vistay.user.profile-linked";
    public static final String PROFILE_LINK_REQUESTED = "vistay.user.profile-link-requested";
    public static final String AUTHORIZATION_CHANGED = "vistay.user.authorization-changed";

    private final JdbcClient jdbc;
    private final IdentityProtection protection;
    private final AuthorizationSnapshotService snapshots;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;
    private final SecureRandom random;

    @Autowired
    public ProfileIdentityLinkService(
        JdbcClient jdbc,
        IdentityProtection protection,
        AuthorizationSnapshotService snapshots,
        TransactionTemplate transactions,
        ObjectMapper json
    ) {
        this(jdbc, protection, snapshots, transactions, json, new SecureRandom());
    }

    ProfileIdentityLinkService(
        JdbcClient jdbc,
        IdentityProtection protection,
        AuthorizationSnapshotService snapshots,
        TransactionTemplate transactions,
        ObjectMapper json,
        SecureRandom random
    ) {
        this.jdbc = jdbc;
        this.protection = protection;
        this.snapshots = snapshots;
        this.transactions = transactions;
        this.json = json;
        this.random = random;
    }

    public ProtectedIdentityView protectProfileDocument(
        UUID actorAccountId,
        String profileType,
        UUID profileId,
        String cccd,
        long expectedProfileVersion,
        String reason
    ) {
        var actor = snapshots.get("ADMIN", actorAccountId);
        if (!actor.active() || !actor.allows("identity-document:manage", Scope.ALL)) {
            throw error("FORBIDDEN", "Identity document management requires ALL scope");
        }
        var type = profileType(profileType);
        var normalized = cccd(cccd);
        var protectedDocument = protect(() -> protection.protectCccd(normalized));
        var normalizedReason = reason(reason);

        return transactions.execute(status -> {
            var profile = lockProfile(type, profileId);
            if (profile.version() != expectedProfileVersion) {
                throw error("PROFILE_VERSION_CONFLICT", "Profile changed before identity protection completed");
            }
            if (document(type, profileId) != null) {
                throw error("IDENTITY_DOCUMENT_ALREADY_EXISTS", "Profile already has a protected CCCD");
            }
            try {
                var row = jdbc.sql("""
                    INSERT INTO profile_identity_documents(
                        profile_type, profile_id, lookup_hmac, lookup_key_version,
                        encrypted_value, encryption_key_version, assurance_level,
                        verified_by_subject_id
                    ) VALUES (
                        :profileType, :profileId, :lookupHmac, :lookupVersion,
                        :ciphertext, :encryptionVersion, 'MANUALLY_VERIFIED', :actorSubjectId
                    )
                    RETURNING id, profile_type, profile_id, lookup_key_version,
                              encryption_key_version, assurance_level, row_version, created_at
                    """)
                    .param("profileType", type)
                    .param("profileId", profileId)
                    .param("lookupHmac", protectedDocument.lookupHmac())
                    .param("lookupVersion", protectedDocument.lookupKeyVersion())
                    .param("ciphertext", protectedDocument.ciphertext())
                    .param("encryptionVersion", protectedDocument.encryptionKeyVersion())
                    .param("actorSubjectId", actor.subjectId())
                    .query(ProtectedIdentityView.class)
                    .single();
                incrementProfileVersion(type, profileId, expectedProfileVersion);
                audit(actor.subjectId(), type, profileId, "IDENTITY_DOCUMENT_PROTECTED", normalizedReason,
                    Map.of("lookupKeyVersion", row.lookupKeyVersion(),
                        "encryptionKeyVersion", row.encryptionKeyVersion()));
                return row;
            } catch (DataIntegrityViolationException collision) {
                throw error("IDENTITY_DOCUMENT_CONFLICT", "CCCD is already assigned inside this profile type");
            }
        });
    }

    public LinkView requestLink(RequestLink command) {
        var type = profileType(command.accountType());
        if (!command.emailVerified()) {
            throw error("ACCOUNT_EMAIL_NOT_VERIFIED", "Account email must be verified before profile linking");
        }
        var accountEmail = email(command.accountEmail());
        var normalizedCccd = cccd(command.cccd());
        ensurePendingSubject(type, command.accountId(), accountEmail);
        var lookup = protect(() -> protection.hmacCccd(normalizedCccd));
        var candidate = findCandidate(type, lookup.value());

        if (candidate == null) {
            if (!"CUSTOMER".equals(type)) {
                return new LinkView(null, null, type, "PROFILE_REQUIRED", null, null, true, false);
            }
            var protectedDocument = protect(() -> protection.protectCccd(normalizedCccd));
            return createCustomer(command.accountId(), accountEmail, displayName(command.displayName()), protectedDocument);
        }
        if (candidate.authAccountId() != null || activeLink(type, candidate.profileId()) != null) {
            return new LinkView(null, null, type, "REVIEW_REQUIRED", null, null, true, false);
        }
        if (candidate.email() == null || candidate.email().isBlank()) {
            return new LinkView(null, null, type, "REVIEW_REQUIRED", null, null, true, false);
        }

        var policy = policy(type);
        var linkId = UUID.randomUUID();
        var challengeId = UUID.randomUUID();
        var otp = "%06d".formatted(random.nextInt(1_000_000));
        var evidence = otpEvidence(challengeId, command.accountId(), candidate.profileId(), otp);
        var otpHmac = protect(() -> protection.hmacOtpEvidence(evidence));
        var delivery = protect(() -> protection.encryptOtpDelivery(String.join("\n",
            "profile-link-email-v1", challengeId.toString(), candidate.email(), otp)));
        var expiresAt = OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(policy.otpTtlSeconds());
        var masked = mask(candidate.email());

        try {
            return transactions.execute(status -> {
                lockProfile(type, candidate.profileId());
                if (activeLink(type, candidate.profileId()) != null) {
                    throw error("PROFILE_LINK_CONFLICT", "Profile is no longer available for linking");
                }
                jdbc.sql("""
                    INSERT INTO profile_account_links(
                        id, profile_type, profile_id, auth_account_id, status, link_method, reason
                    ) VALUES (
                        :id, :profileType, :profileId, :accountId, 'CHALLENGE_ISSUED',
                        'CCCD_EMAIL_OTP', 'Self-service CCCD and profile-email challenge'
                    )
                    """)
                    .param("id", linkId).param("profileType", type)
                    .param("profileId", candidate.profileId()).param("accountId", command.accountId())
                    .update();
                jdbc.sql("""
                    INSERT INTO profile_link_challenges(
                        id, link_id, recipient_email, masked_recipient, otp_hmac,
                        otp_key_version, delivery_ciphertext, delivery_key_version,
                        max_attempts, expires_at
                    ) VALUES (
                        :id, :linkId, :recipient, :masked, :otpHmac,
                        :otpVersion, :deliveryCiphertext, :deliveryVersion,
                        :maxAttempts, :expiresAt
                    )
                    """)
                    .param("id", challengeId).param("linkId", linkId)
                    .param("recipient", candidate.email()).param("masked", masked)
                    .param("otpHmac", otpHmac.value()).param("otpVersion", otpHmac.keyVersion())
                    .param("deliveryCiphertext", delivery.value()).param("deliveryVersion", delivery.keyVersion())
                    .param("maxAttempts", policy.maxOtpAttempts()).param("expiresAt", expiresAt)
                    .update();
                outbox("ProfileAccountLink", linkId, 1, CHALLENGE_ISSUED, Map.of(
                    "linkId", linkId,
                    "challengeId", challengeId,
                    "profileType", type,
                    "maskedRecipient", masked,
                    "deliveryCiphertext", delivery.value(),
                    "deliveryKeyVersion", delivery.keyVersion(),
                    "expiresAt", expiresAt
                ));
                return new LinkView(linkId, challengeId, type, "CHALLENGE_ISSUED",
                    masked, expiresAt, policy.requiresApproval(), false);
            });
        } catch (DataIntegrityViolationException collision) {
            return new LinkView(null, null, type, "REVIEW_REQUIRED", null, null, true, false);
        }
    }

    /**
     * Creates the least-privilege authorization subject used before a profile is linked.
     * This is invoked only for an authenticated, email-verified portal identity whose
     * subject does not exist in User Service yet.
     */
    public void provisionPendingAccount(
        UUID accountId,
        String accountType,
        String accountEmail,
        boolean emailVerified
    ) {
        if (!emailVerified) {
            throw error("ACCOUNT_EMAIL_NOT_VERIFIED", "Account email must be verified before profile linking");
        }
        ensurePendingSubject(profileType(accountType), accountId, email(accountEmail));
    }

    public LinkView verifyLink(UUID accountId, UUID challengeId, String otp) {
        var challenge = challenge(challengeId, accountId, false);
        if (!"DELIVERED".equals(challenge.status())) {
            throw error("LINK_CHALLENGE_NOT_DELIVERED", "Email challenge is not ready for verification");
        }
        if (challenge.expiresAt().isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            expireChallenge(challengeId, challenge.linkId());
            throw error("LINK_CHALLENGE_EXPIRED", "Email challenge expired");
        }
        if (challenge.failedAttempts() >= challenge.maxAttempts()) {
            throw error("LINK_CHALLENGE_LOCKED", "Email challenge is locked");
        }
        var normalizedOtp = otp == null ? "" : otp.trim();
        if (!normalizedOtp.matches("^[0-9]{6}$")) {
            failAttempt(challenge);
            throw error("LINK_CHALLENGE_INVALID", "Email challenge code is invalid");
        }
        var actual = protect(() -> protection.hmacOtpEvidence(
            otpEvidence(challengeId, accountId, challenge.profileId(), normalizedOtp)
        ));
        if (!MessageDigest.isEqual(
            challenge.otpHmac().getBytes(StandardCharsets.US_ASCII),
            actual.value().getBytes(StandardCharsets.US_ASCII)
        )) {
            failAttempt(challenge);
            throw error("LINK_CHALLENGE_INVALID", "Email challenge code is invalid");
        }

        return transactions.execute(status -> {
            var locked = challenge(challengeId, accountId, true);
            if (!"DELIVERED".equals(locked.status())
                || locked.expiresAt().isBefore(OffsetDateTime.now(ZoneOffset.UTC))
                || !MessageDigest.isEqual(
                    locked.otpHmac().getBytes(StandardCharsets.US_ASCII),
                    actual.value().getBytes(StandardCharsets.US_ASCII)
                )) {
                throw error("PROFILE_LINK_CONFLICT", "Profile link challenge changed concurrently");
            }
            var policy = policy(locked.profileType());
            if (policy.requiresApproval()) {
                jdbc.sql("""
                    UPDATE profile_link_challenges
                    SET status = 'VERIFIED', verified_at = now(), updated_at = now()
                    WHERE id = :id AND status = 'DELIVERED'
                    """).param("id", challengeId).update();
                jdbc.sql("""
                    UPDATE profile_account_links
                    SET status = 'APPROVAL_PENDING', evidence_verified_at = now(),
                        row_version = row_version + 1, updated_at = now()
                    WHERE id = :id AND status = 'CHALLENGE_ISSUED'
                    """).param("id", locked.linkId()).update();
                return view(locked.linkId(), challengeId, "APPROVAL_PENDING", true, false);
            }
            jdbc.sql("""
                UPDATE profile_link_challenges
                SET status = 'VERIFIED', verified_at = now(), updated_at = now()
                WHERE id = :id AND status = 'DELIVERED'
                """).param("id", challengeId).update();
            return link(locked.linkId(), null, "Email challenge verified", false);
        });
    }

    public LinkView approveLink(UUID actorAccountId, UUID linkId, String reason) {
        var actor = snapshots.get("ADMIN", actorAccountId);
        if (!actor.active() || !actor.allows("identity-link:approve", Scope.ALL)) {
            throw error("FORBIDDEN", "Profile link approval requires ALL scope");
        }
        var current = linkRow(linkId, false);
        if (current.authAccountId().equals(actorAccountId)) {
            throw error("MAKER_CHECKER_VIOLATION", "A requester cannot approve their own profile link");
        }
        if (!"APPROVAL_PENDING".equals(current.status())) {
            throw error("PROFILE_LINK_NOT_APPROVABLE", "Profile link is not awaiting approval");
        }
        return link(linkId, actor.subjectId(), reason(reason), false);
    }

    public List<ReviewLinkView> reviewQueue(
        UUID actorAccountId,
        String profileType,
        String status,
        Integer first
    ) {
        var actor = snapshots.get("ADMIN", actorAccountId);
        if (!actor.active() || !actor.allows("identity-link:read", Scope.ALL)) {
            throw error("FORBIDDEN", "Profile link review requires ALL scope");
        }
        var normalizedStatus = reviewStatus(status);
        var normalizedType = profileType == null ? null : profileType(profileType);
        var limit = first == null ? 50 : Math.max(1, Math.min(first, 100));
        return jdbc.sql("""
            SELECT l.id AS link_id, l.profile_type, l.profile_id, l.auth_account_id,
                   l.status, l.link_method, l.requested_at,
                   c.masked_recipient,
                   CASE l.profile_type
                     WHEN 'CUSTOMER' THEN (SELECT full_name FROM customers WHERE id = l.profile_id)
                     WHEN 'HOST' THEN (SELECT full_name FROM hosts WHERE id = l.profile_id)
                     WHEN 'ADMIN' THEN (SELECT full_name FROM admin_users WHERE id = l.profile_id)
                   END AS display_name
            FROM profile_account_links l
            LEFT JOIN LATERAL (
                SELECT masked_recipient FROM profile_link_challenges
                WHERE link_id = l.id ORDER BY created_at DESC LIMIT 1
            ) c ON true
            WHERE l.status = :status
              AND (:profileType IS NULL OR l.profile_type = :profileType)
            ORDER BY l.requested_at ASC, l.id ASC
            LIMIT :limit
            """)
            .param("status", normalizedStatus)
            .param("profileType", normalizedType, java.sql.Types.VARCHAR)
            .param("limit", limit)
            .query(ReviewLinkView.class).list();
    }

    public LinkView rejectLink(UUID actorAccountId, UUID linkId, String reason) {
        var actor = snapshots.get("ADMIN", actorAccountId);
        if (!actor.active() || !actor.allows("identity-link:reject", Scope.ALL)) {
            throw error("FORBIDDEN", "Profile link rejection requires ALL scope");
        }
        var normalizedReason = reason(reason);
        return transactions.execute(status -> {
            var current = linkRow(linkId, true);
            if (current.authAccountId().equals(actorAccountId)) {
                throw error("MAKER_CHECKER_VIOLATION", "A requester cannot reject their own profile link");
            }
            if (!"APPROVAL_PENDING".equals(current.status())) {
                throw error("PROFILE_LINK_NOT_REJECTABLE", "Profile link is not awaiting approval");
            }
            jdbc.sql("""
                UPDATE profile_link_challenges
                SET status = 'CANCELLED', updated_at = now()
                WHERE link_id = :linkId AND status IN ('PENDING_DELIVERY', 'DELIVERED', 'VERIFIED')
                """).param("linkId", linkId).update();
            jdbc.sql("""
                UPDATE profile_account_links
                SET status = 'REJECTED', approved_by_subject_id = :actorSubjectId,
                    reason = :reason, row_version = row_version + 1, updated_at = now()
                WHERE id = :linkId AND status = 'APPROVAL_PENDING'
                """)
                .param("actorSubjectId", actor.subjectId()).param("reason", normalizedReason)
                .param("linkId", linkId).update();
            audit(actor.subjectId(), current.profileType(), current.profileId(),
                "PROFILE_LINK_REJECTED", normalizedReason, Map.of("linkId", linkId));
            return view(linkId, null, "REJECTED", true, false);
        });
    }

    public LinkView linkStatus(UUID accountId, String accountType) {
        var type = profileType(accountType);
        var row = jdbc.sql("""
            SELECT id, profile_type, status
            FROM profile_account_links
            WHERE profile_type = :profileType AND auth_account_id = :accountId
            ORDER BY created_at DESC LIMIT 1
            """)
            .param("profileType", type).param("accountId", accountId)
            .query(LinkStatusRow.class).optional().orElse(null);
        if (row == null) return new LinkView(null, null, type, "IDENTITY_PENDING", null, null, false, false);
        return view(row.id(), null, row.status(), policy(type).requiresApproval(), false);
    }

    private LinkView createCustomer(
        UUID accountId,
        String email,
        String displayName,
        IdentityProtection.ProtectedDocument document
    ) {
        try {
            return transactions.execute(status -> {
                var subject = jdbc.sql("""
                    INSERT INTO authorization_subjects(account_type, auth_account_id, active)
                    VALUES ('CUSTOMER', :accountId, true)
                    ON CONFLICT (account_type, auth_account_id) DO UPDATE
                    SET authorization_version = authorization_subjects.authorization_version + 1,
                        updated_at = now()
                    RETURNING id, authorization_version, active
                    """).param("accountId", accountId).query(SubjectRow.class).single();
                if (!subject.active()) throw error("ACCOUNT_DISABLED", "Account authorization subject is disabled");
                var profileId = UUID.randomUUID();
                jdbc.sql("""
                    INSERT INTO customers(
                        id, auth_account_id, authorization_subject_id, full_name, email,
                        profile_status, version
                    ) VALUES (
                        :id, :accountId, :subjectId, :displayName, :email, 'ACTIVE', 1
                    )
                    """)
                    .param("id", profileId).param("accountId", accountId)
                    .param("subjectId", subject.id()).param("displayName", displayName)
                    .param("email", email).update();
                jdbc.sql("""
                    INSERT INTO profile_identity_documents(
                        profile_type, profile_id, lookup_hmac, lookup_key_version,
                        encrypted_value, encryption_key_version, assurance_level
                    ) VALUES (
                        'CUSTOMER', :profileId, :lookupHmac, :lookupVersion,
                        :ciphertext, :encryptionVersion, 'SELF_DECLARED'
                    )
                    """)
                    .param("profileId", profileId).param("lookupHmac", document.lookupHmac())
                    .param("lookupVersion", document.lookupKeyVersion())
                    .param("ciphertext", document.ciphertext())
                    .param("encryptionVersion", document.encryptionKeyVersion()).update();
                var linkId = UUID.randomUUID();
                jdbc.sql("""
                    INSERT INTO profile_account_links(
                        id, profile_type, profile_id, auth_account_id, status, link_method,
                        evidence_verified_at, approved_at, linked_at, reason
                    ) VALUES (
                        :id, 'CUSTOMER', :profileId, :accountId, 'LINKED', 'CUSTOMER_SELF_CREATE',
                        now(), now(), now(), 'Verified email and self-declared CCCD'
                    )
                    """)
                    .param("id", linkId).param("profileId", profileId).param("accountId", accountId)
                    .update();
                revokePendingRole(subject.id());
                assignDefaultRole(subject.id(), "CUSTOMER_MEMBER");
                authorizationChanged(subject.id(), accountId, "CUSTOMER", subject.authorizationVersion());
                outbox("ProfileAccountLink", linkId, 1, PROFILE_LINKED, Map.of(
                    "linkId", linkId, "profileId", profileId, "accountId", accountId,
                    "profileType", "CUSTOMER", "authorizationVersion", subject.authorizationVersion()
                ));
                return new LinkView(linkId, null, "CUSTOMER", "LINKED", null, null, false, false);
            });
        } catch (DataIntegrityViolationException collision) {
            return new LinkView(null, null, "CUSTOMER", "REVIEW_REQUIRED", null, null, true, false);
        }
    }

    private LinkView link(UUID linkId, UUID approverSubjectId, String reason, boolean replayed) {
        return transactions.execute(status -> {
            var current = linkRow(linkId, true);
            if ("LINKED".equals(current.status())) {
                return view(linkId, null, "LINKED", policy(current.profileType()).requiresApproval(), true);
            }
            if (!"CHALLENGE_ISSUED".equals(current.status())
                && !"APPROVAL_PENDING".equals(current.status())) {
                throw error("PROFILE_LINK_CONFLICT", "Profile link can no longer be completed");
            }
            var profile = lockProfile(current.profileType(), current.profileId());
            if (profile.authAccountId() != null && !profile.authAccountId().equals(current.authAccountId())) {
                jdbc.sql("UPDATE profile_account_links SET status = 'CONFLICT', updated_at = now() WHERE id = :id")
                    .param("id", linkId).update();
                throw error("PROFILE_LINK_CONFLICT", "Profile is no longer available for linking");
            }
            var subject = jdbc.sql("""
                INSERT INTO authorization_subjects(account_type, auth_account_id, active)
                VALUES (:profileType, :accountId, true)
                ON CONFLICT (account_type, auth_account_id) DO UPDATE
                SET authorization_version = authorization_subjects.authorization_version + 1,
                    updated_at = now()
                RETURNING id, authorization_version, active
                """)
                .param("profileType", current.profileType()).param("accountId", current.authAccountId())
                .query(SubjectRow.class).single();
            if (!subject.active()) throw error("ACCOUNT_DISABLED", "Account authorization subject is disabled");
            attachProfile(current.profileType(), current.profileId(), current.authAccountId(), subject.id());
            revokePendingRole(subject.id());
            assignDefaultRole(subject.id(), defaultRole(current.profileType()));
            jdbc.sql("""
                UPDATE profile_account_links
                SET status = 'LINKED', approved_at = COALESCE(approved_at, now()),
                    approved_by_subject_id = COALESCE(:approver, approved_by_subject_id),
                    linked_at = now(), reason = :reason,
                    row_version = row_version + 1, updated_at = now()
                WHERE id = :id
                """)
                .param("approver", approverSubjectId, java.sql.Types.OTHER)
                .param("reason", reason).param("id", linkId).update();
            outbox("ProfileAccountLink", linkId, current.rowVersion() + 1, PROFILE_LINKED, Map.of(
                "linkId", linkId, "profileId", current.profileId(), "accountId", current.authAccountId(),
                "profileType", current.profileType(), "authorizationVersion", subject.authorizationVersion()
            ));
            authorizationChanged(subject.id(), current.authAccountId(), current.profileType(),
                subject.authorizationVersion());
            snapshots.evict(current.profileType(), current.authAccountId());
            return view(linkId, null, "LINKED", policy(current.profileType()).requiresApproval(), replayed);
        });
    }

    private void attachProfile(String type, UUID profileId, UUID accountId, UUID subjectId) {
        var table = table(type);
        var updated = jdbc.sql("""
            UPDATE %s SET auth_account_id = :accountId, authorization_subject_id = :subjectId,
                          version = version + 1, updated_at = now()
            WHERE id = :profileId AND auth_account_id IS NULL
            """.formatted(table))
            .param("accountId", accountId).param("subjectId", subjectId).param("profileId", profileId)
            .update();
        if (updated != 1) throw error("PROFILE_LINK_CONFLICT", "Profile is no longer available for linking");
    }

    private void assignDefaultRole(UUID subjectId, String roleCode) {
        if (roleCode == null) return;
        var assignment = jdbc.sql("""
            INSERT INTO subject_role_assignments(subject_id, role_id)
            SELECT :subjectId, id FROM roles WHERE code = :roleCode AND active
            ON CONFLICT DO NOTHING
            RETURNING id
            """).param("subjectId", subjectId).param("roleCode", roleCode)
            .query(UUID.class).optional().orElse(null);
        if (assignment == null) return;
        jdbc.sql("""
            INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
            SELECT :assignmentId, rpp.permission_id, rpp.scope_type
            FROM role_permission_policies rpp
            JOIN roles r ON r.id = rpp.role_id
            WHERE r.code = :roleCode AND rpp.default_scope
            ON CONFLICT DO NOTHING
            """).param("assignmentId", assignment).param("roleCode", roleCode).update();
    }

    private void ensurePendingSubject(String type, UUID accountId, String accountEmail) {
        transactions.executeWithoutResult(status -> {
            var subject = jdbc.sql("""
                INSERT INTO authorization_subjects(account_type, auth_account_id, active)
                VALUES (:type, :accountId, true)
                ON CONFLICT (account_type, auth_account_id) DO NOTHING
                RETURNING id, authorization_version, active
                """)
                .param("type", type).param("accountId", accountId)
                .query(SubjectRow.class).optional().orElseGet(() -> jdbc.sql("""
                    SELECT id, authorization_version, active
                    FROM authorization_subjects
                    WHERE account_type = :type AND auth_account_id = :accountId
                    """)
                    .param("type", type).param("accountId", accountId)
                    .query(SubjectRow.class).single());
            if (!subject.active()) {
                throw error("ACCOUNT_DISABLED", "Account authorization subject is disabled");
            }
            var assignmentId = jdbc.sql("""
                INSERT INTO subject_role_assignments(subject_id, role_id)
                SELECT :subjectId, id FROM roles WHERE code = :roleCode AND active
                ON CONFLICT DO NOTHING
                RETURNING id
                """)
                .param("subjectId", subject.id()).param("roleCode", pendingRole(type))
                .query(UUID.class).optional().orElse(null);
            if (assignmentId == null) return;
            jdbc.sql("""
                INSERT INTO subject_role_permission_scopes(assignment_id, permission_id, scope_type)
                SELECT :assignmentId, rpp.permission_id, rpp.scope_type
                FROM role_permission_policies rpp
                JOIN roles r ON r.id = rpp.role_id
                WHERE r.code = :roleCode AND rpp.default_scope
                ON CONFLICT DO NOTHING
                """)
                .param("assignmentId", assignmentId).param("roleCode", pendingRole(type)).update();
            var version = jdbc.sql("""
                UPDATE authorization_subjects
                SET authorization_version = authorization_version + 1, updated_at = now()
                WHERE id = :id RETURNING authorization_version
                """).param("id", subject.id()).query(Long.class).single();
            authorizationChanged(subject.id(), accountId, type, version);
            outbox("AuthorizationSubject", subject.id(), version, PROFILE_LINK_REQUESTED, Map.of(
                "accountId", accountId,
                "accountType", type,
                "email", accountEmail,
                "requestedAt", OffsetDateTime.now(ZoneOffset.UTC)
            ));
            snapshots.evict(type, accountId);
        });
    }

    private void revokePendingRole(UUID subjectId) {
        jdbc.sql("""
            UPDATE subject_role_assignments sra
            SET revoked_at = now(), revoke_reason = 'Profile account link completed'
            FROM roles r
            WHERE sra.role_id = r.id AND sra.subject_id = :subjectId
              AND r.code IN ('CUSTOMER_IDENTITY_PENDING', 'HOST_IDENTITY_PENDING', 'ADMIN_IDENTITY_PENDING')
              AND sra.revoked_at IS NULL
            """).param("subjectId", subjectId).update();
    }

    private void authorizationChanged(UUID subjectId, UUID accountId, String accountType, long version) {
        outbox("AuthorizationSubject", subjectId, version, AUTHORIZATION_CHANGED, Map.of(
            "accountId", accountId,
            "accountType", accountType,
            "authorizationVersion", version,
            "changedAt", OffsetDateTime.now(ZoneOffset.UTC)
        ));
    }

    private Candidate findCandidate(String type, String lookupHmac) {
        var table = table(type);
        return jdbc.sql("""
            SELECT d.profile_id, p.auth_account_id, p.email::text AS email
            FROM profile_identity_documents d
            JOIN %s p ON p.id = d.profile_id
            WHERE d.profile_type = :profileType
              AND d.document_country = 'VN' AND d.document_type = 'CCCD'
              AND d.lookup_hmac = :lookupHmac
            """.formatted(table))
            .param("profileType", type).param("lookupHmac", lookupHmac)
            .query(Candidate.class).optional().orElse(null);
    }

    private LinkRow activeLink(String type, UUID profileId) {
        return jdbc.sql("""
            SELECT id, profile_type, profile_id, auth_account_id, status, row_version
            FROM profile_account_links
            WHERE profile_type = :profileType AND profile_id = :profileId
              AND status IN ('REQUESTED', 'CHALLENGE_ISSUED', 'EVIDENCE_VERIFIED', 'APPROVAL_PENDING', 'LINKED')
            """).param("profileType", type).param("profileId", profileId)
            .query(LinkRow.class).optional().orElse(null);
    }

    private LinkRow linkRow(UUID linkId, boolean lock) {
        return jdbc.sql("""
            SELECT id, profile_type, profile_id, auth_account_id, status, row_version
            FROM profile_account_links WHERE id = :id
            """ + (lock ? " FOR UPDATE" : ""))
            .param("id", linkId).query(LinkRow.class).optional()
            .orElseThrow(() -> error("PROFILE_LINK_NOT_FOUND", "Profile link was not found"));
    }

    private ChallengeRow challenge(UUID challengeId, UUID accountId, boolean lock) {
        return jdbc.sql("""
            SELECT c.id, c.link_id, l.profile_type, l.profile_id, l.auth_account_id,
                   c.otp_hmac, c.status, c.failed_attempts, c.max_attempts, c.expires_at
            FROM profile_link_challenges c
            JOIN profile_account_links l ON l.id = c.link_id
            WHERE c.id = :challengeId AND l.auth_account_id = :accountId
            """ + (lock ? " FOR UPDATE" : ""))
            .param("challengeId", challengeId).param("accountId", accountId)
            .query(ChallengeRow.class).optional()
            .orElseThrow(() -> error("LINK_CHALLENGE_NOT_FOUND", "Email challenge was not found"));
    }

    private ProfileRow lockProfile(String type, UUID profileId) {
        return jdbc.sql("""
            SELECT id, auth_account_id, version FROM %s WHERE id = :profileId FOR UPDATE
            """.formatted(table(type)))
            .param("profileId", profileId).query(ProfileRow.class).optional()
            .orElseThrow(() -> error("PROFILE_NOT_FOUND", "Profile was not found"));
    }

    private DocumentRow document(String type, UUID profileId) {
        return jdbc.sql("""
            SELECT id FROM profile_identity_documents
            WHERE profile_type = :profileType AND profile_id = :profileId
              AND document_country = 'VN' AND document_type = 'CCCD'
            """).param("profileType", type).param("profileId", profileId)
            .query(DocumentRow.class).optional().orElse(null);
    }

    private PolicyRow policy(String type) {
        return jdbc.sql("""
            SELECT account_type,
                   EXTRACT(EPOCH FROM otp_ttl)::bigint AS otp_ttl_seconds,
                   max_otp_attempts, requires_approval
            FROM profile_link_policies WHERE account_type = :type AND active
            """).param("type", type).query(PolicyRow.class).optional()
            .orElseThrow(() -> error("PROFILE_LINK_POLICY_UNAVAILABLE", "Profile link policy is unavailable"));
    }

    private void incrementProfileVersion(String type, UUID profileId, long expectedVersion) {
        var updated = jdbc.sql("""
            UPDATE %s SET version = version + 1, updated_at = now()
            WHERE id = :profileId AND version = :version
            """.formatted(table(type)))
            .param("profileId", profileId).param("version", expectedVersion).update();
        if (updated != 1) throw error("PROFILE_VERSION_CONFLICT", "Profile changed concurrently");
    }

    private void failAttempt(ChallengeRow challenge) {
        var next = challenge.failedAttempts() + 1;
        jdbc.sql("""
            UPDATE profile_link_challenges
            SET failed_attempts = :attempts,
                status = CASE WHEN :attempts >= max_attempts THEN 'LOCKED' ELSE status END,
                updated_at = now()
            WHERE id = :id
            """).param("attempts", next).param("id", challenge.id()).update();
    }

    private void expireChallenge(UUID challengeId, UUID linkId) {
        transactions.executeWithoutResult(status -> {
            jdbc.sql("UPDATE profile_link_challenges SET status = 'EXPIRED', updated_at = now() WHERE id = :id")
                .param("id", challengeId).update();
            jdbc.sql("UPDATE profile_account_links SET status = 'EXPIRED', updated_at = now() WHERE id = :id")
                .param("id", linkId).update();
        });
    }

    private LinkView view(UUID linkId, UUID challengeId, String status, boolean requiresApproval, boolean replayed) {
        var challenge = challengeId == null ? jdbc.sql("""
            SELECT id, masked_recipient, expires_at FROM profile_link_challenges
            WHERE link_id = :linkId ORDER BY created_at DESC LIMIT 1
            """).param("linkId", linkId).query(ChallengeViewRow.class).optional().orElse(null) : null;
        var row = linkRow(linkId, false);
        return new LinkView(linkId,
            challengeId == null && challenge != null ? challenge.id() : challengeId,
            row.profileType(), status,
            challenge == null ? null : challenge.maskedRecipient(),
            challenge == null ? null : challenge.expiresAt(), requiresApproval, replayed);
    }

    private void audit(UUID actorSubjectId, String type, UUID profileId, String action, String reason,
                       Map<String, Object> changes) {
        jdbc.sql("""
            INSERT INTO audit_events(
                actor_admin_user_id, action, aggregate_type, aggregate_id,
                changes, correlation_id, reason
            ) VALUES (
                (SELECT id FROM admin_users WHERE authorization_subject_id = :actorSubjectId),
                :action, :aggregateType, :aggregateId, CAST(:changes AS jsonb), :correlation, :reason
            )
            """)
            .param("actorSubjectId", actorSubjectId).param("action", action)
            .param("aggregateType", type + "Profile").param("aggregateId", profileId)
            .param("changes", writeJson(changes)).param("correlation", UUID.randomUUID().toString())
            .param("reason", reason).update();
    }

    private void outbox(String aggregateType, UUID aggregateId, long version, String eventType,
                        Map<String, Object> payload) {
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id
            ) VALUES (
                :aggregateType, :aggregateId, :version, :eventType,
                1, CAST(:payload AS jsonb), :correlationId
            )
            """)
            .param("aggregateType", aggregateType).param("aggregateId", aggregateId)
            .param("version", version).param("eventType", eventType)
            .param("payload", writeJson(payload)).param("correlationId", UUID.randomUUID().toString())
            .update();
    }

    private String writeJson(Object value) {
        try { return json.writeValueAsString(value); }
        catch (JacksonException failure) { throw new IllegalStateException("Cannot serialize profile link event", failure); }
    }

    private static <T> T protect(ProtectedOperation<T> operation) {
        try { return operation.get(); }
        catch (RuntimeException unavailable) {
            if (unavailable instanceof IllegalArgumentException) throw unavailable;
            throw error("IDENTITY_PROTECTION_UNAVAILABLE", "Identity protection is temporarily unavailable");
        }
    }

    private static String table(String type) {
        return switch (type) {
            case "CUSTOMER" -> "customers";
            case "ADMIN" -> "admin_users";
            case "HOST" -> "hosts";
            default -> throw new IllegalArgumentException("Unsupported profile type");
        };
    }

    private static String defaultRole(String type) {
        return switch (type) {
            case "CUSTOMER" -> "CUSTOMER_MEMBER";
            case "HOST" -> "HOST_PARTNER";
            case "ADMIN" -> null;
            default -> null;
        };
    }

    private static String pendingRole(String type) {
        return switch (type) {
            case "CUSTOMER" -> "CUSTOMER_IDENTITY_PENDING";
            case "HOST" -> "HOST_IDENTITY_PENDING";
            case "ADMIN" -> "ADMIN_IDENTITY_PENDING";
            default -> throw new IllegalArgumentException("Unsupported profile type");
        };
    }

    private static String profileType(String value) {
        var type = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!type.matches("CUSTOMER|ADMIN|HOST")) throw error("INVALID_PROFILE_TYPE", "Unsupported profile type");
        return type;
    }

    private static String cccd(String value) {
        var normalized = value == null ? "" : value.replaceAll("\\s", "");
        if (!normalized.matches("^[0-9]{12}$")) throw error("INVALID_CCCD", "CCCD must contain exactly 12 digits");
        return normalized;
    }

    private static String email(String value) {
        var normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$") || normalized.length() > 254) {
            throw error("INVALID_ACCOUNT_EMAIL", "Verified account email is invalid");
        }
        return normalized;
    }

    private static String displayName(String value) {
        var normalized = value == null ? "" : value.trim().replaceAll("\\s+", " ");
        if (normalized.isEmpty() || normalized.length() > 180) {
            throw error("INVALID_DISPLAY_NAME", "Display name must contain 1 to 180 characters");
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

    private static String reviewStatus(String value) {
        var normalized = value == null ? "APPROVAL_PENDING" : value.trim().toUpperCase(Locale.ROOT);
        if (!normalized.matches("APPROVAL_PENDING|REJECTED|LINKED|EXPIRED|CONFLICT")) {
            throw error("INVALID_PROFILE_LINK_STATUS", "Unsupported profile link review status");
        }
        return normalized;
    }

    private static String mask(String email) {
        var at = email.indexOf('@');
        var local = email.substring(0, at);
        var visible = local.substring(0, 1);
        return visible + "***" + email.substring(at);
    }

    private static String otpEvidence(UUID challengeId, UUID accountId, UUID profileId, String otp) {
        return String.join("\n", "profile-link-otp-v1", challengeId.toString(), accountId.toString(),
            profileId.toString(), otp);
    }

    private static GraphqlErrorException error(String code, String message) {
        var classification = switch (code) {
            case "FORBIDDEN" -> ErrorType.FORBIDDEN;
            case "PROFILE_NOT_FOUND", "PROFILE_LINK_NOT_FOUND", "LINK_CHALLENGE_NOT_FOUND" -> ErrorType.NOT_FOUND;
            default -> ErrorType.BAD_REQUEST;
        };
        return GraphqlErrorException.newErrorException().message(message)
            .errorClassification(classification).extensions(Map.of("code", code)).build();
    }

    @FunctionalInterface
    private interface ProtectedOperation<T> { T get(); }

    private record Candidate(UUID profileId, UUID authAccountId, String email) {}
    private record ProfileRow(UUID id, UUID authAccountId, long version) {}
    private record DocumentRow(UUID id) {}
    private record SubjectRow(UUID id, long authorizationVersion, boolean active) {}
    private record LinkRow(UUID id, String profileType, UUID profileId, UUID authAccountId,
                           String status, long rowVersion) {}
    private record LinkStatusRow(UUID id, String profileType, String status) {}
    private record ChallengeRow(UUID id, UUID linkId, String profileType, UUID profileId,
                                UUID authAccountId, String otpHmac, String status,
                                int failedAttempts, int maxAttempts, OffsetDateTime expiresAt) {}
    private record ChallengeViewRow(UUID id, String maskedRecipient, OffsetDateTime expiresAt) {}
    private record PolicyRow(String accountType, long otpTtlSeconds, int maxOtpAttempts,
                             boolean requiresApproval) {}

    public record RequestLink(UUID accountId, String accountType, String accountEmail,
                              boolean emailVerified, String displayName, String cccd) {}

    public record ProtectedIdentityView(UUID id, String profileType, UUID profileId,
                                        int lookupKeyVersion, int encryptionKeyVersion,
                                        String assuranceLevel, long rowVersion,
                                        OffsetDateTime createdAt) {}

    public record LinkView(UUID linkId, UUID challengeId, String profileType, String status,
                           String maskedRecipient, OffsetDateTime expiresAt,
                           boolean requiresApproval, boolean replayed) {}

    public record ReviewLinkView(UUID linkId, String profileType, UUID profileId,
                                 UUID authAccountId, String status, String linkMethod,
                                 OffsetDateTime requestedAt, String maskedRecipient,
                                 String displayName) {}
}
