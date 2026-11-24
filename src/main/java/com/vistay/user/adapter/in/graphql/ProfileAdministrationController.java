package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.ProfileAdministrationService;
import com.vistay.user.application.ProfileAdministrationService.AdminDraft;
import com.vistay.user.application.ProfileAdministrationService.CustomerDraft;
import com.vistay.user.application.ProfileAdministrationService.CustomerContactAvailability;
import com.vistay.user.application.ProfileAdministrationService.HostDraft;
import com.vistay.user.application.ProfileAdministrationService.IdentityDocumentAvailability;
import com.vistay.user.application.ProfileAdministrationService.ProfileView;
import com.vistay.user.observability.UserBusinessMetrics;
import java.util.UUID;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class ProfileAdministrationController {
    private final ProfileAdministrationService profiles;
    private final UserBusinessMetrics metrics;

    public ProfileAdministrationController(ProfileAdministrationService profiles, UserBusinessMetrics metrics) {
        this.profiles = profiles;
        this.metrics = metrics;
    }

    @QueryMapping
    @RequiresPermission("user:read")
    public ProfileView userProfile(@Argument String accountType, @Argument UUID profileId) {
        return profiles.find(accountType, profileId);
    }

    @QueryMapping
    @RequiresPermission("customer-profile:create")
    public IdentityDocumentAvailability customerIdentityDocumentAvailability(
        @Argument String nationalityCode,
        @Argument String documentType,
        @Argument String documentNumber
    ) {
        return profiles.customerIdentityDocumentAvailability(
            nationalityCode, documentType, documentNumber
        );
    }

    @QueryMapping
    @RequiresPermission("customer-profile:create")
    public CustomerContactAvailability customerContactAvailability(
        @Argument String email,
        @Argument String contactPhone
    ) {
        return profiles.customerContactAvailability(email, contactPhone);
    }

    @MutationMapping
    @RequiresPermission("customer-profile:create")
    public ProfileView createCustomerProfile(
        @AuthenticationPrincipal Jwt jwt,
        @Argument CreateCustomerProfileInput input
    ) {
        var profile = profiles.createCustomer(ViewerQuery.accountId(jwt), new CustomerDraft(
            input.fullName(), input.email(), input.contactPhone(), input.dateOfBirth(),
            input.nationalityCode(), input.documentType(), input.documentNumber(),
            input.address(), input.reason(), input.idempotencyKey()
        ));
        metrics.profileCreated("CUSTOMER");
        return profile;
    }

    @MutationMapping
    @RequiresPermission("admin-profile:create")
    public ProfileView createAdminProfile(
        @AuthenticationPrincipal Jwt jwt,
        @Argument CreateAdminProfileInput input
    ) {
        var profile = profiles.createAdmin(ViewerQuery.accountId(jwt), new AdminDraft(
            input.fullName(), input.email(), input.contactPhone(), input.employeeCode(),
            input.subtype(), input.hiredOn(), input.reason(), input.idempotencyKey()
        ));
        metrics.profileCreated("ADMIN");
        return profile;
    }

    @MutationMapping
    @RequiresPermission("host-profile:create")
    public ProfileView createHostProfile(
        @AuthenticationPrincipal Jwt jwt,
        @Argument CreateHostProfileInput input
    ) {
        var profile = profiles.createHost(ViewerQuery.accountId(jwt), new HostDraft(
            input.fullName(), input.email(), input.contactPhone(), input.hostCode(),
            input.address(), input.taxCode(), input.reason(), input.idempotencyKey()
        ));
        metrics.profileCreated("HOST");
        return profile;
    }

    public record CreateCustomerProfileInput(
        String fullName, String email, String contactPhone, String dateOfBirth,
        String nationalityCode, String documentType, String documentNumber,
        String address, String reason, String idempotencyKey
    ) {}

    public record CreateAdminProfileInput(
        String fullName, String email, String contactPhone, String employeeCode,
        String subtype, String hiredOn, String reason, String idempotencyKey
    ) {}

    public record CreateHostProfileInput(
        String fullName, String email, String contactPhone, String hostCode,
        String address, String taxCode, String reason, String idempotencyKey
    ) {}
}
