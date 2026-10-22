package com.vistay.user.adapter.in.messaging;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Component
public class AccountProvisionedListener {
    public static final String EVENT_TYPE = "vistay.auth.account-provisioned";
    public static final String PROFILE_PROVISIONED = "vistay.user.profile-provisioned";
    private static final String CONSUMER_NAME = "user-account-provisioning-v1";

    private final JdbcClient jdbc;
    private final ObjectMapper json;

    public AccountProvisionedListener(JdbcClient jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    @KafkaListener(
        topics = "${vistay.topics.account-provisioned:vistay.auth.account-provisioned.v1}",
        groupId = "${spring.kafka.consumer.group-id:vistay-user}"
    )
    @Transactional
    public void onAccountProvisioned(String rawEnvelope) throws Exception {
        var envelope = json.readValue(rawEnvelope, EventEnvelope.class);
        if (!EVENT_TYPE.equals(envelope.type()) || envelope.version() != 1) {
            throw new IllegalArgumentException("Unsupported account provisioning event");
        }
        if (!markProcessed(envelope.eventId())) {
            return;
        }

        var data = envelope.data();
        var accountId = UUID.fromString(requiredText(data, "accountId"));
        var fullName = requiredText(data, "displayName");
        var email = requiredText(data, "email");
        var profile = jdbc.sql("""
            INSERT INTO admin_users(
                auth_account_id, full_name, email, user_type, profile_status, version
            )
            VALUES (:accountId, :fullName, :email, 'ADMIN', 'ACTIVE', 1)
            ON CONFLICT (auth_account_id) DO UPDATE
            SET full_name = EXCLUDED.full_name,
                email = EXCLUDED.email,
                updated_at = now(),
                version = admin_users.version + 1
            RETURNING id, version
            """)
            .param("accountId", accountId)
            .param("fullName", fullName)
            .param("email", email)
            .query(ProfileProvisionedRow.class)
            .single();

        jdbc.sql("""
            INSERT INTO admin_user_roles(admin_user_id, role_id)
            SELECT :profileId, id FROM roles WHERE code = 'SUPER_ADMIN'
            ON CONFLICT DO NOTHING
            """)
            .param("profileId", profile.id())
            .update();

        var payload = json.writeValueAsString(new ProfileProvisionedData(
            accountId,
            profile.id(),
            "BACKOFFICE",
            email,
            fullName,
            profile.version(),
            OffsetDateTime.now()
        ));
        jdbc.sql("""
            INSERT INTO outbox_events(
                aggregate_type, aggregate_id, aggregate_version, event_type,
                event_version, payload, correlation_id, causation_id
            ) VALUES (
                'AdminProfile', :profileId, :aggregateVersion, :eventType,
                1, CAST(:payload AS jsonb), :correlationId, :causationId
            )
            """)
            .param("profileId", profile.id())
            .param("aggregateVersion", profile.version())
            .param("eventType", PROFILE_PROVISIONED)
            .param("payload", payload)
            .param("correlationId", envelope.correlationId())
            .param("causationId", envelope.eventId().toString())
            .update();
    }

    private boolean markProcessed(UUID eventId) {
        try {
            return jdbc.sql("""
                INSERT INTO processed_events(event_id, consumer_name)
                VALUES (:eventId, :consumerName)
                ON CONFLICT DO NOTHING
                """)
                .param("eventId", eventId)
                .param("consumerName", CONSUMER_NAME)
                .update() == 1;
        } catch (DataIntegrityViolationException duplicate) {
            return false;
        }
    }

    private static String requiredText(JsonNode data, String field) {
        var node = data.get(field);
        if (node == null || node.asString().isBlank()) {
            throw new IllegalArgumentException("Missing event data field: " + field);
        }
        return node.asString();
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

    private record ProfileProvisionedData(
        UUID accountId,
        UUID profileId,
        String realm,
        String email,
        String displayName,
        long authorizationVersion,
        OffsetDateTime provisionedAt
    ) {}

    record ProfileProvisionedRow(UUID id, long version) {}
}
