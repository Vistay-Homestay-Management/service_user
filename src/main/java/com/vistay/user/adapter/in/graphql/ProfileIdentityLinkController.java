package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.ProfileIdentityLinkService;
import com.vistay.user.application.ProfileIdentityLinkService.LinkView;
import com.vistay.user.application.ProfileIdentityLinkService.ProtectedIdentityView;
import com.vistay.user.application.ProfileIdentityLinkService.RequestLink;
import graphql.GraphqlErrorException;
import java.util.Locale;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class ProfileIdentityLinkController {
    private final ProfileIdentityLinkService links;

    public ProfileIdentityLinkController(ProfileIdentityLinkService links) {
        this.links = links;
    }

    @QueryMapping
    @RequiresPermission("identity-link:read")
    public LinkView myProfileLinkStatus(@AuthenticationPrincipal Jwt jwt) {
        return links.linkStatus(ViewerQuery.accountId(jwt), accountType(jwt));
    }

    @QueryMapping
    @RequiresPermission("identity-link:read")
    public List<ProfileIdentityLinkService.ReviewLinkView> profileLinkRequests(
        @AuthenticationPrincipal Jwt jwt,
        @Argument String profileType,
        @Argument String status,
        @Argument Integer first
    ) {
        return links.reviewQueue(ViewerQuery.accountId(jwt), profileType, status, first);
    }

    @MutationMapping
    @RequiresPermission("identity-document:manage")
    public ProtectedIdentityView protectProfileIdentityDocument(
        @AuthenticationPrincipal Jwt jwt,
        @Argument ProtectProfileIdentityDocumentInput input
    ) {
        return links.protectProfileDocument(
            ViewerQuery.accountId(jwt), input.profileType(), input.profileId(), input.cccd(),
            input.expectedProfileVersion(), input.reason()
        );
    }

    @MutationMapping
    @RequiresPermission("identity-link:request")
    public LinkView requestMyProfileLink(
        @AuthenticationPrincipal Jwt jwt,
        @Argument RequestProfileLinkInput input
    ) {
        return links.requestLink(new RequestLink(
            ViewerQuery.accountId(jwt), accountType(jwt), jwt.getClaimAsString("email"),
            Boolean.TRUE.equals(jwt.getClaim("email_verified")), input.displayName(), input.cccd()
        ));
    }

    @MutationMapping
    @RequiresPermission("identity-link:verify")
    public LinkView verifyMyProfileLink(
        @AuthenticationPrincipal Jwt jwt,
        @Argument VerifyProfileLinkInput input
    ) {
        return links.verifyLink(ViewerQuery.accountId(jwt), input.challengeId(), input.code());
    }

    @MutationMapping
    @RequiresPermission("identity-link:approve")
    public LinkView approveProfileLink(
        @AuthenticationPrincipal Jwt jwt,
        @Argument ApproveProfileLinkInput input
    ) {
        return links.approveLink(ViewerQuery.accountId(jwt), input.linkId(), input.reason());
    }

    @MutationMapping
    @RequiresPermission("identity-link:reject")
    public LinkView rejectProfileLink(
        @AuthenticationPrincipal Jwt jwt,
        @Argument RejectProfileLinkInput input
    ) {
        return links.rejectLink(ViewerQuery.accountId(jwt), input.linkId(), input.reason());
    }

    private static String accountType(Jwt jwt) {
        var explicit = jwt.getClaimAsString("account_type");
        if (explicit != null && !explicit.isBlank()) return normalizeType(explicit);
        var issuer = jwt.getIssuer() == null ? "" : jwt.getIssuer().toString();
        if (issuer.contains("vistay-customer")) return "CUSTOMER";
        if (issuer.contains("vistay-host")) return "HOST";
        if (issuer.contains("vistay-backoffice")) return "ADMIN";
        throw GraphqlErrorException.newErrorException()
            .message("JWT does not identify a supported ViStay portal")
            .errorClassification(ErrorType.FORBIDDEN)
            .extensions(Map.of("code", "ACCOUNT_TYPE_UNAVAILABLE"))
            .build();
    }

    private static String normalizeType(String value) {
        var type = value.trim().toUpperCase(Locale.ROOT);
        if (!type.matches("CUSTOMER|ADMIN|HOST")) {
            throw GraphqlErrorException.newErrorException()
                .message("JWT account type is unsupported")
                .errorClassification(ErrorType.FORBIDDEN)
                .extensions(Map.of("code", "ACCOUNT_TYPE_UNAVAILABLE"))
                .build();
        }
        return type;
    }

    public record ProtectProfileIdentityDocumentInput(
        String profileType,
        UUID profileId,
        String cccd,
        long expectedProfileVersion,
        String reason
    ) {}

    public record RequestProfileLinkInput(String displayName, String cccd) {}
    public record VerifyProfileLinkInput(UUID challengeId, String code) {}
    public record ApproveProfileLinkInput(UUID linkId, String reason) {}
    public record RejectProfileLinkInput(UUID linkId, String reason) {}
}
