package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.AuthorizationManagementService;
import com.vistay.user.application.AuthorizationManagementService.AuditView;
import com.vistay.user.application.AuthorizationManagementService.ChangeInput;
import com.vistay.user.application.AuthorizationManagementService.ChangeRequestView;
import com.vistay.user.application.AuthorizationManagementService.ReductionInput;
import com.vistay.user.application.AuthorizationManagementService.RoleView;
import com.vistay.user.application.AuthorizationManagementService.SubjectView;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import graphql.GraphqlErrorException;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class AuthorizationController {
    private final AuthorizationManagementService authorizations;

    public AuthorizationController(AuthorizationManagementService authorizations) {
        this.authorizations = authorizations;
    }

    @QueryMapping
    public List<RoleView> authorizationCatalog(@AuthenticationPrincipal Jwt jwt, @Argument String accountType) {
        return authorizations.catalog(ViewerQuery.accountId(jwt), accountType);
    }

    @QueryMapping
    public SubjectView authorizationSubject(@AuthenticationPrincipal Jwt jwt, @Argument UUID subjectId) {
        return authorizations.subject(ViewerQuery.accountId(jwt), subjectId);
    }

    @QueryMapping
    public SubjectView authorizationSubjectByAccount(
        @AuthenticationPrincipal Jwt jwt,
        @Argument String accountType,
        @Argument UUID accountId
    ) {
        return authorizations.subjectByAccount(ViewerQuery.accountId(jwt), accountType, accountId);
    }

    @QueryMapping
    public List<ChangeRequestView> authorizationChangeRequests(
        @AuthenticationPrincipal Jwt jwt,
        @Argument String status
    ) {
        return authorizations.changeRequests(ViewerQuery.accountId(jwt), status == null ? "PENDING" : status);
    }

    @QueryMapping
    public List<AuditView> authorizationAudit(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UUID targetSubjectId
    ) {
        return authorizations.audit(ViewerQuery.accountId(jwt), targetSubjectId);
    }

    @MutationMapping
    public ChangeRequestView requestAuthorizationChange(
        @AuthenticationPrincipal Jwt jwt,
        @Argument ChangeInput input
    ) {
        return authorizations.requestChange(ViewerQuery.accountId(jwt), input);
    }

    @MutationMapping
    public ChangeRequestView approveAuthorizationChange(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UUID id,
        @Argument String reason,
        @Argument long expectedAuthorizationVersion
    ) {
        var result = authorizations.approve(ViewerQuery.accountId(jwt), id, reason, expectedAuthorizationVersion);
        if ("STALE".equals(result.status())) {
            throw GraphqlErrorException.newErrorException()
                .message("Authorization request is stale")
                .errorClassification(ErrorType.BAD_REQUEST)
                .extensions(Map.of("code", "VERSION_CONFLICT"))
                .build();
        }
        return result;
    }

    @MutationMapping
    public ChangeRequestView rejectAuthorizationChange(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UUID id,
        @Argument String reason
    ) {
        return authorizations.reject(ViewerQuery.accountId(jwt), id, reason);
    }

    @MutationMapping
    public SubjectView revokeRoleAssignment(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UUID assignmentId,
        @Argument String reason,
        @Argument long expectedAuthorizationVersion
    ) {
        return authorizations.revoke(ViewerQuery.accountId(jwt), assignmentId, reason, expectedAuthorizationVersion);
    }

    @MutationMapping
    public SubjectView reduceAuthorizationScopes(
        @AuthenticationPrincipal Jwt jwt,
        @Argument ReductionInput input
    ) {
        return authorizations.reduce(ViewerQuery.accountId(jwt), input);
    }

    @MutationMapping
    public SubjectView establishSecondApprover(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UUID targetSubjectId,
        @Argument String reason
    ) {
        return authorizations.establishSecondApprover(ViewerQuery.accountId(jwt), targetSubjectId, reason);
    }
}
