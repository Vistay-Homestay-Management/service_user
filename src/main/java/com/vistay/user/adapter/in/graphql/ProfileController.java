package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.ProfileService;
import com.vistay.user.application.ProfileService.PersonalProfile;
import com.vistay.user.application.ProfileService.UpdateProfileInput;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class ProfileController {
    private final ProfileService profiles;

    public ProfileController(ProfileService profiles) {
        this.profiles = profiles;
    }

    @QueryMapping
    public PersonalProfile myProfile(@AuthenticationPrincipal Jwt jwt) {
        return profiles.get(ViewerQuery.accountId(jwt));
    }

    @MutationMapping
    public PersonalProfile updateMyProfile(
        @AuthenticationPrincipal Jwt jwt,
        @Argument UpdateProfileInput input
    ) {
        return profiles.update(ViewerQuery.accountId(jwt), input);
    }
}
