package com.vistay.user.adapter.in.messaging;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccountProvisionedListenerTest {
    @Mock
    private JdbcClient jdbc;

    private final ObjectMapper json = JsonMapper.builder().build();

    @Test
    void createsOnlyOneProfileWhenKafkaRedeliversTheSameEvent() throws Exception {
        var eventId = UUID.randomUUID();
        var accountId = UUID.randomUUID();
        var profileId = UUID.randomUUID();

        var processed = mock(JdbcClient.StatementSpec.class);
        var profile = mock(JdbcClient.StatementSpec.class);
        var role = mock(JdbcClient.StatementSpec.class);
        var outbox = mock(JdbcClient.StatementSpec.class);
        var profileQuery = mock(JdbcClient.MappedQuerySpec.class);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO processed_events")))
            .thenReturn(processed);
        when(processed.param(anyString(), any())).thenReturn(processed);
        when(processed.update()).thenReturn(1, 0);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO admin_users")))
            .thenReturn(profile);
        when(profile.param(anyString(), any())).thenReturn(profile);
        when(profile.query(UUID.class)).thenReturn(profileQuery);
        when(profileQuery.single()).thenReturn(profileId);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO admin_user_roles")))
            .thenReturn(role);
        when(role.param(anyString(), any())).thenReturn(role);
        when(role.update()).thenReturn(1);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO outbox_events")))
            .thenReturn(outbox);
        when(outbox.param(anyString(), any())).thenReturn(outbox);
        when(outbox.update()).thenReturn(1);

        var envelope = """
            {
              "eventId":"%s",
              "type":"vistay.auth.account-provisioned",
              "version":1,
              "aggregateId":"%s",
              "aggregateVersion":0,
              "correlationId":"corr-1",
              "causationId":null,
              "occurredAt":"%s",
              "data":{
                "identityAccountId":"%s",
                "subject":"%s",
                "email":"admin@vistay.vn",
                "fullName":"ViStay Admin",
                "accountType":"ADMIN"
              }
            }
            """.formatted(eventId, accountId, OffsetDateTime.now(), accountId, accountId);

        var listener = new AccountProvisionedListener(jdbc, json);
        listener.onAccountProvisioned(envelope);
        listener.onAccountProvisioned(envelope);

        verify(profile, times(1)).query(UUID.class);
        verify(outbox, times(1)).update();
    }
}
