package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.RolePolicyManagementService;
import com.vistay.user.application.RolePolicyManagementService.ChangeRequestView;
import com.vistay.user.application.RolePolicyManagementService.CreateRoleInput;
import com.vistay.user.application.RolePolicyManagementService.DeactivateRoleInput;
import com.vistay.user.application.RolePolicyManagementService.PermissionChangeInput;
import com.vistay.user.application.RolePolicyManagementService.PermissionView;
import com.vistay.user.application.RolePolicyManagementService.RoleView;
import graphql.GraphqlErrorException;
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
public class RolePolicyController {
    private final RolePolicyManagementService roles;

    public RolePolicyController(RolePolicyManagementService roles) {
        this.roles = roles;
    }

    @QueryMapping
    public List<RoleView> roleCatalog(@AuthenticationPrincipal Jwt jwt, @Argument String accountType) {
        return roles.catalog(ViewerQuery.accountId(jwt), accountType);
    }

    @QueryMapping
    public RoleView role(
        @AuthenticationPrincipal Jwt jwt,
        @Argument String accountType,
        @Argument String code
    ) {
        return roles.role(ViewerQuery.accountId(jwt), accountType, code);
    }

    @QueryMapping
    public List<PermissionView> permissionCatalog(@AuthenticationPrincipal Jwt jwt) {
        return roles.permissionCatalog(ViewerQuery.accountId(jwt));
    }

    @QueryMapping
    public List<ChangeRequestView> rolePolicyChangeRequests(
        @AuthenticationPrincipal Jwt jwt,
        @Argument String status
    ) {
        return roles.changeRequests(ViewerQuery.accountId(jwt), status);
    }

    @MutationMapping
    public ChangeRequestView requestCreateRole(
        @AuthenticationPrincipal Jwt jwt,
        @Argument CreateRoleInput input
    ) {
        return roles.requestCreate(ViewerQuery.accountId(jwt), input);
    }

    @MutationMapping
    public ChangeRequestView requestRolePermissionChange(
        @AuthenticationPrincipal Jwt jwt,
        @Argument PermissionChangeInput input
    ) {
        return roles.requestPermissionChange(ViewerQuery.accountId(jwt), input);
    }

    @MutationMapping
    public ChangeRequestView requestDeactivateRole(
        @AuthenticationPrincipal Jwt jwt,
        @Argument DeactivateRoleInput input
    ) {
        return roles.requestDeactivate(ViewerQuery.accountId(jwt), input);
    }

    @MutationMapping
    public ChangeRequestView approveRolePolicyChange(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UUID id,
        @Argument String reason
    ) {
        var result = roles.approve(ViewerQuery.accountId(jwt), id, reason);
        if ("STALE".equals(result.status())) {
            throw GraphqlErrorException.newErrorException()
                .message("Role-policy request is stale")
                .errorClassification(ErrorType.BAD_REQUEST)
                .extensions(Map.of("code", "ROLE_VERSION_CONFLICT"))
                .build();
        }
        return result;
    }

    @MutationMapping
    public ChangeRequestView rejectRolePolicyChange(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UUID id,
        @Argument String reason
    ) {
        return roles.reject(ViewerQuery.accountId(jwt), id, reason);
    }
}
