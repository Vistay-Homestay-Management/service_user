package com.vistay.user.application;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

/** Turns time expiry into an explicit versioned revocation event. */
@Component
public class ExpiredRoleAssignmentReconciler {
    private final JdbcClient jdbc;
    private final ObjectMapper json;

    public ExpiredRoleAssignmentReconciler(JdbcClient jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    @Scheduled(fixedDelayString = "${vistay.authorization.expiry-reconcile-delay-ms:30000}")
    @Transactional
    public void reconcile() {
        var subjects = jdbc.sql("""
                SELECT s.id, s.account_type, s.auth_account_id
                FROM authorization_subjects s
                WHERE EXISTS (
                    SELECT 1 FROM subject_role_assignments assignment
                    WHERE assignment.subject_id = s.id
                      AND assignment.revoked_at IS NULL
                      AND assignment.valid_until IS NOT NULL
                      AND assignment.valid_until <= now()
                )
                ORDER BY s.id
                FOR UPDATE SKIP LOCKED
                LIMIT 100
                """).query(SubjectRow.class).list();
        for (var subject : subjects) reconcile(subject);
    }

    private void reconcile(SubjectRow subject) {
        var expired = jdbc.sql("""
                UPDATE subject_role_assignments
                SET revoked_at = now(), revoke_reason = 'ROLE_ASSIGNMENT_EXPIRED'
                WHERE subject_id = :subjectId AND revoked_at IS NULL
                  AND valid_until IS NOT NULL AND valid_until <= now()
                RETURNING id
                """).param("subjectId", subject.id()).query(UUID.class).list();
        if (expired.isEmpty()) return;
        var version = jdbc.sql("""
                UPDATE authorization_subjects
                SET authorization_version = authorization_version + 1, updated_at = now()
                WHERE id = :id RETURNING authorization_version
                """).param("id", subject.id()).query(Long.class).single();
        var payload = json.writeValueAsString(Map.of(
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
        jdbc.sql("""
                INSERT INTO authorization_audit_events(target_subject_id, action,
                    before_state, after_state, reason)
                VALUES (:subjectId, 'ROLE_ASSIGNMENTS_EXPIRED', CAST(:before AS jsonb),
                    CAST(:after AS jsonb), 'Time-bounded role assignment expiry reconciliation')
                """).param("subjectId", subject.id())
            .param("before", json.writeValueAsString(Map.of("assignmentIds", expired)))
            .param("after", json.writeValueAsString(Map.of("authorizationVersion", version)))
            .update();
    }

    private record SubjectRow(UUID id, String accountType, UUID authAccountId) {}
}
