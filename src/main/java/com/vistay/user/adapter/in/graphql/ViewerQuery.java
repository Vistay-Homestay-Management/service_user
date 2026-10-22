package com.vistay.user.adapter.in.graphql;

import graphql.GraphqlErrorException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class ViewerQuery {
    private final JdbcClient jdbc;

    public ViewerQuery(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @QueryMapping
    public BackofficeViewer viewer(@AuthenticationPrincipal Jwt jwt) {
        if (jwt == null) {
            throw GraphqlErrorException.newErrorException()
                .message("Authentication is required")
                .extensions(Map.of("code", "UNAUTHENTICATED"))
                .build();
        }

        UUID accountId;
        try {
            accountId = UUID.fromString(jwt.getSubject());
        } catch (IllegalArgumentException invalidSubject) {
            throw GraphqlErrorException.newErrorException()
                .message("The token subject is not a ViStay account id")
                .extensions(Map.of("code", "INVALID_TOKEN"))
                .build();
        }

        var profile = jdbc.sql("""
            SELECT id, full_name, email::text AS email, version
            FROM admin_users
            WHERE auth_account_id = :accountId AND profile_status = 'ACTIVE'
            """)
            .param("accountId", accountId)
            .query(ProfileRow.class)
            .optional()
            .orElseThrow(() -> GraphqlErrorException.newErrorException()
                .message("Backoffice profile is not provisioned")
                .extensions(Map.of("code", "PROFILE_NOT_PROVISIONED"))
                .build());

        var roles = jdbc.sql("""
            SELECT r.code FROM admin_user_roles aur
            JOIN roles r ON r.id = aur.role_id
            WHERE aur.admin_user_id = :profileId
              AND aur.revoked_at IS NULL
              AND aur.valid_from <= now()
              AND (aur.valid_until IS NULL OR aur.valid_until > now())
              AND r.active
            ORDER BY r.code
            """)
            .param("profileId", profile.id())
            .query(String.class)
            .list();
        var permissions = jdbc.sql("""
            SELECT DISTINCT p.code FROM admin_user_roles aur
            JOIN roles r ON r.id = aur.role_id AND r.active
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE aur.admin_user_id = :profileId
              AND aur.revoked_at IS NULL
              AND aur.valid_from <= now()
              AND (aur.valid_until IS NULL OR aur.valid_until > now())
            ORDER BY p.code
            """)
            .param("profileId", profile.id())
            .query(String.class)
            .list();
        return new BackofficeViewer(
            accountId,
            profile.id(),
            profile.fullName(),
            profile.email(),
            roles,
            permissions,
            profile.version()
        );
    }

    private record ProfileRow(UUID id, String fullName, String email, long version) {}

    public record BackofficeViewer(
        UUID accountId,
        UUID profileId,
        String displayName,
        String email,
        List<String> roles,
        List<String> permissions,
        long authorizationVersion
    ) {}
}
