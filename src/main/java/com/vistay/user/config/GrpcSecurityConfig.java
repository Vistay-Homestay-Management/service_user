package com.vistay.user.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
public class GrpcSecurityConfig {

    @Bean
    UserDetailsService grpcClientDetails() {
        return certificatePrincipal -> User.withUsername(certificatePrincipal)
            .password("")
            .authorities("ROLE_INTERNAL_SERVICE")
            .build();
    }

    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor grpcSecurityFilterChain(GrpcSecurity grpc) throws Exception {
        return grpc
            .authorizeRequests(requests -> requests.allRequests().authenticated())
            .preauth(withDefaults())
            .build();
    }
}
