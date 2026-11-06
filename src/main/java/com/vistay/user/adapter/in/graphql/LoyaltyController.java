package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.LoyaltyProgramService;
import com.vistay.user.application.LoyaltyProgramService.ChangeRequestView;
import com.vistay.user.application.LoyaltyProgramService.LoyaltyProfile;
import com.vistay.user.application.LoyaltyProgramService.PointAdjustmentInput;
import com.vistay.user.application.LoyaltyProgramService.ProgramChangeInput;
import com.vistay.user.application.LoyaltyProgramService.ProgramView;
import java.util.List;
import java.util.UUID;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class LoyaltyController {
    private final LoyaltyProgramService loyalty;

    public LoyaltyController(LoyaltyProgramService loyalty) {
        this.loyalty = loyalty;
    }

    @QueryMapping
    @RequiresPermission("loyalty-profile:read")
    public LoyaltyProfile myLoyaltyProfile(@AuthenticationPrincipal Jwt jwt) {
        return loyalty.myProfile(ViewerQuery.accountId(jwt));
    }

    @QueryMapping
    @RequiresPermission("loyalty-program:read")
    public List<ProgramView> loyaltyPrograms(@AuthenticationPrincipal Jwt jwt) {
        return loyalty.catalog(ViewerQuery.accountId(jwt));
    }

    @QueryMapping
    @RequiresPermission("loyalty-program:read")
    public List<ChangeRequestView> loyaltyProgramChangeRequests(@AuthenticationPrincipal Jwt jwt,
        @Argument String status) {
        return loyalty.changeRequests(ViewerQuery.accountId(jwt), status);
    }

    @MutationMapping
    @RequiresPermission("loyalty-program:change-request")
    public ChangeRequestView requestLoyaltyProgramChange(@AuthenticationPrincipal Jwt jwt,
        @Argument ProgramChangeInput input) {
        return loyalty.requestChange(ViewerQuery.accountId(jwt), input);
    }

    @MutationMapping
    @RequiresPermission("loyalty-program:change-approve")
    public ChangeRequestView approveLoyaltyProgramChange(@AuthenticationPrincipal Jwt jwt,
        @Argument UUID id, @Argument String reason) {
        return loyalty.approve(ViewerQuery.accountId(jwt), id, reason);
    }

    @MutationMapping
    @RequiresPermission("loyalty-program:change-approve")
    public ChangeRequestView rejectLoyaltyProgramChange(@AuthenticationPrincipal Jwt jwt,
        @Argument UUID id, @Argument String reason) {
        return loyalty.reject(ViewerQuery.accountId(jwt), id, reason);
    }

    @MutationMapping
    @RequiresPermission("loyalty-point:adjust")
    public LoyaltyProfile adjustQualifyingPoints(@AuthenticationPrincipal Jwt jwt,
        @Argument PointAdjustmentInput input) {
        return loyalty.adjustPoints(ViewerQuery.accountId(jwt), input);
    }
}
