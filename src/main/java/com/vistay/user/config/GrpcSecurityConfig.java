package com.vistay.user.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;

@Configuration
public class GrpcSecurityConfig {

    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor grpcSecurityFilterChain(GrpcSecurity grpc) throws Exception {
        return grpc
            .authorizeRequests(requests -> requests.allRequests().authenticated())
            .preauth(withDefaults())
            .build();
    }
}
