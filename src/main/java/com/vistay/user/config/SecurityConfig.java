package com.vistay.user.config;

import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    JwtDecoder jwtDecoder(
        @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String adminIssuer,
        @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String adminJwks,
        @Value("${vistay.security.audience}") String adminAudience,
        @Value("${vistay.security.customer-issuer:http://identity.localhost/realms/vistay-customer}") String customerIssuer,
        @Value("${vistay.security.customer-jwks:http://localhost:8180/realms/vistay-customer/protocol/openid-connect/certs}") String customerJwks,
        @Value("${vistay.security.customer-audience:vistay-customer-api}") String customerAudience,
        @Value("${vistay.security.host-issuer:http://identity.localhost/realms/vistay-host}") String hostIssuer,
        @Value("${vistay.security.host-jwks:http://localhost:8180/realms/vistay-host/protocol/openid-connect/certs}") String hostJwks,
        @Value("${vistay.security.host-audience:vistay-host-api}") String hostAudience
    ) {
        Map<String, JwtDecoder> delegates = new LinkedHashMap<>();
        delegates.put(adminIssuer, decoder(adminIssuer, adminJwks, adminAudience, "ADMIN"));
        delegates.put(customerIssuer, decoder(customerIssuer, customerJwks, customerAudience, "CUSTOMER"));
        delegates.put(hostIssuer, decoder(hostIssuer, hostJwks, hostAudience, "HOST"));
        return token -> {
            try {
                var issuer = SignedJWT.parse(token).getJWTClaimsSet().getIssuer();
                var delegate = delegates.get(issuer);
                if (delegate == null) throw new JwtException("Untrusted ViStay token issuer");
                return delegate.decode(token);
            } catch (ParseException invalid) {
                throw new JwtException("Malformed JWT", invalid);
            }
        };
    }

    private static JwtDecoder decoder(String issuer, String jwks, String audience, String accountType) {
        var decoder = NimbusJwtDecoder.withJwkSetUri(jwks).build();
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> withAudience = token -> token.getAudience().contains(audience)
            ? OAuth2TokenValidatorResult.success()
            : OAuth2TokenValidatorResult.failure(new OAuth2Error(
                "invalid_token", "Required audience is missing", null));
        OAuth2TokenValidator<Jwt> withAccountType = token -> accountType.equals(token.getClaimAsString("account_type"))
            ? OAuth2TokenValidatorResult.success()
            : OAuth2TokenValidatorResult.failure(new OAuth2Error(
                "invalid_token", "Required account_type is missing", null));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.of(
            withIssuer, withAudience, withAccountType)));
        return decoder;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health/**", "/actuator/info", "/actuator/prometheus").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults())).build();
    }
}
