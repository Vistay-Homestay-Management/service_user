package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.IdentityPolicyService;
import com.vistay.user.application.IdentityPolicyService.Change;
import com.vistay.user.application.IdentityPolicyService.IdentityPolicyView;
import java.util.List;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class IdentityPolicyController {
    private final IdentityPolicyService policies;

    public IdentityPolicyController(IdentityPolicyService policies) {
        this.policies = policies;
    }

    @QueryMapping
    @RequiresPermission("identity-policy:read")
    public List<IdentityPolicyView> identityPolicies() {
        return policies.list();
    }

    @MutationMapping
    @RequiresPermission("identity-policy:update")
    public IdentityPolicyView updateIdentityPolicy(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UpdateIdentityPolicyInput input
    ) {
        return policies.update(ViewerQuery.accountId(jwt), new Change(
            input.accountType(), input.registrationEnabled(), input.linkMode(),
            input.expectedPolicyVersion(), input.reason(), input.idempotencyKey()
        ));
    }

    public record UpdateIdentityPolicyInput(
        String accountType,
        boolean registrationEnabled,
        String linkMode,
        long expectedPolicyVersion,
        String reason,
        String idempotencyKey
    ) {}
}
