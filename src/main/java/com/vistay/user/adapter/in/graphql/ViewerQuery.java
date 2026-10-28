package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.AuthorizationSnapshotService;
import graphql.GraphqlErrorException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class ViewerQuery {
    private final JdbcClient jdbc;
    private final AuthorizationSnapshotService snapshots;

    public ViewerQuery(JdbcClient jdbc, AuthorizationSnapshotService snapshots) {
        this.jdbc = jdbc;
        this.snapshots = snapshots;
    }

    @QueryMapping
    public BackofficeViewer viewer(@AuthenticationPrincipal Jwt jwt) {
        var accountId = accountId(jwt);
        var snapshot = snapshots.get("ADMIN", accountId);
        if (!snapshot.active() || snapshot.profileId() == null) {
            throw error("PROFILE_NOT_PROVISIONED", "Backoffice profile is not active or provisioned");
        }
        var profile = jdbc.sql("""
                SELECT full_name, email::text AS email, normalized_phone, avatar_media_id, version
                FROM admin_users WHERE id = :profileId
                """)
            .param("profileId", snapshot.profileId())
            .query(ProfileRow.class)
            .single();
        var grants = snapshot.grants().stream()
            .map(grant -> new EffectiveGrant(grant.permissionCode(),
                grant.scopes().stream().map(Enum::name).toList()))
            .toList();
        return new BackofficeViewer(accountId, snapshot.profileId(), profile.fullName(), profile.email(),
            profile.normalizedPhone(), profile.avatarMediaId(), profile.version(), snapshot.roles(),
            snapshot.permissions(), grants, snapshot.authorizationVersion());
    }

    static UUID accountId(Jwt jwt) {
        if (jwt == null) {
            throw error("UNAUTHENTICATED", "Authentication is required");
        }
        try {
            return UUID.fromString(jwt.getSubject());
        } catch (IllegalArgumentException invalidSubject) {
            throw error("INVALID_TOKEN", "The token subject is not a ViStay account id");
        }
    }

    static GraphqlErrorException error(String code, String message) {
        return GraphqlErrorException.newErrorException()
            .message(message)
            .errorClassification(code.endsWith("_NOT_FOUND") ? ErrorType.NOT_FOUND : ErrorType.BAD_REQUEST)
            .extensions(Map.of("code", code))
            .build();
    }

    private record ProfileRow(String fullName, String email, String normalizedPhone,
        UUID avatarMediaId, long version) {}
    public record EffectiveGrant(String permissionCode, List<String> scopes) {}
    public record BackofficeViewer(UUID accountId, UUID profileId, String displayName, String email,
        String contactPhone, UUID avatarMediaId, long profileVersion, List<String> roles,
        List<String> permissions, List<EffectiveGrant> grants, long authorizationVersion) {}
}
