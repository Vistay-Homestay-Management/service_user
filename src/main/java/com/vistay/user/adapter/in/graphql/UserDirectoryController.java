package com.vistay.user.adapter.in.graphql;

import com.vistay.user.application.UserDirectoryService;
import com.vistay.user.application.UserDirectoryService.UserDirectoryPage;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;

@Controller
public class UserDirectoryController {
    private final UserDirectoryService directory;

    public UserDirectoryController(UserDirectoryService directory) {
        this.directory = directory;
    }

    @QueryMapping
    @RequiresPermission("user:read")
    public UserDirectoryPage userDirectory(
        @AuthenticationPrincipal Jwt jwt,
        @Argument String accountType,
        @Argument String search,
        @Argument Integer first,
        @Argument String after
    ) {
        return directory.find(ViewerQuery.accountId(jwt), accountType, search, first, after);
    }
}
