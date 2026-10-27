package com.vistay.user.adapter.in.messaging;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
        var subjectId = UUID.randomUUID();
        var assignmentId = UUID.randomUUID();

        var processed = mock(JdbcClient.StatementSpec.class);
        var subject = mock(JdbcClient.StatementSpec.class);
        var profile = mock(JdbcClient.StatementSpec.class);
        var bootstrapQueryStatement = mock(JdbcClient.StatementSpec.class);
        var role = mock(JdbcClient.StatementSpec.class);
        var assignment = mock(JdbcClient.StatementSpec.class);
        var scopes = mock(JdbcClient.StatementSpec.class);
        var bootstrapUpdate = mock(JdbcClient.StatementSpec.class);
        var outbox = mock(JdbcClient.StatementSpec.class);
        var subjectQuery = mock(JdbcClient.MappedQuerySpec.class);
        var profileQuery = mock(JdbcClient.MappedQuerySpec.class);
        var bootstrapQuery = mock(JdbcClient.MappedQuerySpec.class);
        var assignmentQuery = mock(JdbcClient.MappedQuerySpec.class);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO processed_events")))
            .thenReturn(processed);
        when(processed.param(anyString(), any())).thenReturn(processed);
        when(processed.update()).thenReturn(1, 0);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO authorization_subjects")))
            .thenReturn(subject);
        when(subject.param(anyString(), any())).thenReturn(subject);
        when(subject.query(AccountProvisionedListener.AuthorizationSubjectRow.class)).thenReturn(subjectQuery);
        when(subjectQuery.single()).thenReturn(
            new AccountProvisionedListener.AuthorizationSubjectRow(subjectId, 1)
        );

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO admin_users")))
            .thenReturn(profile);
        when(profile.param(anyString(), any())).thenReturn(profile);
        when(profile.query(AccountProvisionedListener.ProfileProvisionedRow.class)).thenReturn(profileQuery);
        when(profileQuery.single()).thenReturn(
            new AccountProvisionedListener.ProfileProvisionedRow(profileId, 1)
        );

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("SELECT first_super_admin_subject_id")))
            .thenReturn(bootstrapQueryStatement);
        when(bootstrapQueryStatement.query(AccountProvisionedListener.BootstrapRow.class))
            .thenReturn(bootstrapQuery);
        when(bootstrapQuery.single()).thenReturn(new AccountProvisionedListener.BootstrapRow(null));

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO admin_user_roles")))
            .thenReturn(role);
        when(role.param(anyString(), any())).thenReturn(role);
        when(role.update()).thenReturn(1);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO subject_role_assignments")))
            .thenReturn(assignment);
        when(assignment.param(anyString(), any())).thenReturn(assignment);
        when(assignment.query(UUID.class)).thenReturn(assignmentQuery);
        when(assignmentQuery.single()).thenReturn(assignmentId);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("INSERT INTO subject_role_permission_scopes")))
            .thenReturn(scopes);
        when(scopes.param(anyString(), any())).thenReturn(scopes);
        when(scopes.update()).thenReturn(1);

        when(jdbc.sql(org.mockito.ArgumentMatchers.startsWith("UPDATE authorization_bootstrap_state")))
            .thenReturn(bootstrapUpdate);
        when(bootstrapUpdate.param(anyString(), any())).thenReturn(bootstrapUpdate);
        when(bootstrapUpdate.update()).thenReturn(1);

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
              "aggregateVersion":1,
              "correlationId":"%s",
              "causationId":null,
              "occurredAt":"%s",
              "data":{
                "accountId":"%s",
                "realm":"BACKOFFICE",
                "email":"admin@vistay.vn",
                "displayName":"ViStay Admin",
                "provisionedAt":"%s"
              }
            }
            """.formatted(eventId, accountId, UUID.randomUUID(), OffsetDateTime.now(), accountId,
                OffsetDateTime.now());

        var listener = new AccountProvisionedListener(jdbc, json);
        listener.onAccountProvisioned(envelope);
        listener.onAccountProvisioned(envelope);

        verify(profile, times(1)).query(AccountProvisionedListener.ProfileProvisionedRow.class);
        verify(outbox, times(1)).update();
    }
}
