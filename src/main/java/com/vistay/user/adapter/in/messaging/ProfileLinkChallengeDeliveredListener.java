package com.vistay.user.adapter.in.messaging;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Component
public class ProfileLinkChallengeDeliveredListener {
    public static final String EVENT_TYPE = "vistay.user.profile-link-challenge-delivered";
    private static final String CONSUMER_NAME = "user-profile-link-delivery-v1";

    private final JdbcClient jdbc;
    private final ObjectMapper json;

    public ProfileLinkChallengeDeliveredListener(JdbcClient jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    @KafkaListener(
        topics = "${vistay.topics.profile-link-challenge-delivered:vistay.user.profile-link-challenge-delivered.v1}",
        groupId = "${spring.kafka.consumer.group-id:vistay-user}-profile-link-delivery-v1"
    )
    @Transactional
    public void onDelivered(String rawEnvelope) throws Exception {
        var envelope = json.readValue(rawEnvelope, EventEnvelope.class);
        if (!EVENT_TYPE.equals(envelope.type()) || envelope.version() != 1) {
            throw new IllegalArgumentException("Unsupported profile link delivery event");
        }
        if (jdbc.sql("""
            INSERT INTO processed_events(event_id, consumer_name)
            VALUES (:eventId, :consumerName)
            ON CONFLICT DO NOTHING
            """)
            .param("eventId", envelope.eventId()).param("consumerName", CONSUMER_NAME)
            .update() == 0) {
            return;
        }
        var challengeId = UUID.fromString(requiredText(envelope.data(), "challengeId"));
        var linkId = UUID.fromString(requiredText(envelope.data(), "linkId"));
        var deliveredAt = OffsetDateTime.parse(requiredText(envelope.data(), "deliveredAt"));
        var updated = jdbc.sql("""
            UPDATE profile_link_challenges c
            SET status = CASE WHEN c.expires_at > :deliveredAt THEN 'DELIVERED' ELSE 'EXPIRED' END,
                updated_at = now()
            FROM profile_account_links l
            WHERE c.id = :challengeId AND c.link_id = :linkId
              AND l.id = c.link_id
              AND c.status = 'PENDING_DELIVERY'
            """)
            .param("deliveredAt", deliveredAt).param("challengeId", challengeId)
            .param("linkId", linkId).update();
        if (updated == 0) {
            var terminal = jdbc.sql("""
                SELECT count(*)::int FROM profile_link_challenges
                WHERE id = :challengeId AND link_id = :linkId
                  AND status IN ('DELIVERED', 'VERIFIED', 'EXPIRED', 'LOCKED', 'CANCELLED')
                """)
                .param("challengeId", challengeId).param("linkId", linkId)
                .query(Integer.class).single();
            if (terminal == 0) throw new IllegalArgumentException("Profile link challenge delivery mismatch");
        }
    }

    private static String requiredText(JsonNode data, String field) {
        var value = data == null ? null : data.get(field);
        if (value == null || value.asString().isBlank()) {
            throw new IllegalArgumentException("Missing event data field: " + field);
        }
        return value.asString();
    }

    public record EventEnvelope(UUID eventId, String type, int version, UUID aggregateId,
        long aggregateVersion, String correlationId, String causationId, OffsetDateTime occurredAt,
        JsonNode data) {}
}
