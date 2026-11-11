package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.AuthorizationSnapshotService;
import com.vistay.user.application.AuthorizationSnapshotService.Scope;
import com.vistay.user.application.ProfileIdentityLinkService;
import graphql.GraphqlErrorException;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class RequiresPermissionAspect {
    private final AuthorizationSnapshotService snapshots;
    private final ProfileIdentityLinkService profileLinks;

    public RequiresPermissionAspect(
        AuthorizationSnapshotService snapshots,
        ProfileIdentityLinkService profileLinks
    ) {
        this.snapshots = snapshots;
        this.profileLinks = profileLinks;
    }

    @Before("@annotation(requirement)")
    public void enforce(RequiresPermission requirement) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication)
            || !authentication.isAuthenticated()) {
            throw error("UNAUTHENTICATED", "Authentication is required");
        }
        var jwt = jwtAuthentication.getToken();
        UUID accountId;
        try {
            accountId = UUID.fromString(jwt.getSubject());
        } catch (RuntimeException invalid) {
            throw error("INVALID_TOKEN", "Token subject is not a ViStay account id");
        }
        var accountType = accountType(jwt.getClaimAsString("account_type"),
            jwt.getIssuer() == null ? "" : jwt.getIssuer().toString());
        var snapshot = snapshots.get(accountType, accountId);
        if (snapshot.subjectId() == null && requirement.value().startsWith("identity-link:")) {
            profileLinks.provisionPendingAccount(
                accountId,
                accountType,
                jwt.getClaimAsString("email"),
                Boolean.TRUE.equals(jwt.getClaim("email_verified"))
            );
            snapshot = snapshots.get(accountType, accountId);
        }
        if (!snapshot.active() || snapshot.permissions().stream().noneMatch(requirement.value()::equals)) {
            throw error("FORBIDDEN", "Missing required permission: " + requirement.value());
        }
    }

    private static String accountType(String explicit, String issuer) {
        if (explicit != null && !explicit.isBlank()) {
            var normalized = explicit.trim().toUpperCase(Locale.ROOT);
            if (normalized.matches("CUSTOMER|ADMIN|HOST")) return normalized;
        }
        if (issuer.contains("vistay-customer")) return "CUSTOMER";
        if (issuer.contains("vistay-host")) return "HOST";
        if (issuer.contains("vistay-backoffice")) return "ADMIN";
        throw error("ACCOUNT_TYPE_UNAVAILABLE", "Token does not identify a ViStay portal");
    }

    private static GraphqlErrorException error(String code, String message) {
        return GraphqlErrorException.newErrorException()
            .message(message)
            .errorClassification("FORBIDDEN".equals(code) ? ErrorType.FORBIDDEN : ErrorType.UNAUTHORIZED)
            .extensions(Map.of("code", code)).build();
    }
}
