package com.vistay.user.adapter.out.security;

import com.vistay.user.application.IdentityProtection;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class VaultTransitIdentityProtection implements IdentityProtection {
    private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

    private final RestClient vault;
    private final String configuredToken;
    private final String tokenFile;
    private final String transitMount;
    private final String documentKey;
    private final String lookupKey;
    private final String otpKey;
    private final String otpDeliveryKey;

    public VaultTransitIdentityProtection(
        @Value("${vistay.identity-protection.vault.address:http://localhost:8200}") String address,
        @Value("${vistay.identity-protection.vault.token:}") String configuredToken,
        @Value("${vistay.identity-protection.vault.token-file:}") String tokenFile,
        @Value("${vistay.identity-protection.vault.transit-mount:transit}") String transitMount,
        @Value("${vistay.identity-protection.vault.document-key:vistay-profile-document}") String documentKey,
        @Value("${vistay.identity-protection.vault.lookup-key:vistay-profile-lookup}") String lookupKey,
        @Value("${vistay.identity-protection.vault.otp-key:vistay-profile-link-otp}") String otpKey,
        @Value("${vistay.identity-protection.vault.otp-delivery-key:vistay-profile-link-delivery}") String otpDeliveryKey
    ) {
        this.vault = RestClient.builder().baseUrl(withoutTrailingSlash(address)).build();
        this.configuredToken = configuredToken == null ? "" : configuredToken.trim();
        this.tokenFile = tokenFile == null ? "" : tokenFile.trim();
        this.transitMount = pathSegment(transitMount, "transit mount");
        this.documentKey = pathSegment(documentKey, "document key");
        this.lookupKey = pathSegment(lookupKey, "lookup key");
        this.otpKey = pathSegment(otpKey, "OTP HMAC key");
        this.otpDeliveryKey = pathSegment(otpDeliveryKey, "OTP delivery key");
    }

    @Override
    public ProtectedDocument protectCccd(String normalizedCccd) {
        var input = cccdInput(normalizedCccd);
        var lookup = hmac(lookupKey, input);
        var encrypted = encrypt(documentKey, input);
        return new ProtectedDocument(
            lookup.value(), lookup.keyVersion(), encrypted.value(), encrypted.keyVersion()
        );
    }

    @Override
    public ProtectedValue hmacCccd(String normalizedCccd) {
        return hmac(lookupKey, cccdInput(normalizedCccd));
    }

    @Override
    public ProtectedValue hmacOtpEvidence(String canonicalEvidence) {
        return hmac(otpKey, requireValue(canonicalEvidence, "OTP evidence"));
    }

    @Override
    public ProtectedValue encryptOtpDelivery(String canonicalDeliverySecret) {
        return encrypt(otpDeliveryKey, requireValue(canonicalDeliverySecret, "OTP delivery secret"));
    }

    private ProtectedValue hmac(String key, String plaintext) {
        var response = write(
            "/v1/" + transitMount + "/hmac/" + key + "/sha2-256",
            Map.of("input", base64(plaintext))
        );
        return versioned(requireDataValue(response, "hmac"), "Vault HMAC");
    }

    private ProtectedValue encrypt(String key, String plaintext) {
        var response = write(
            "/v1/" + transitMount + "/encrypt/" + key,
            Map.of("plaintext", base64(plaintext))
        );
        return versioned(requireDataValue(response, "ciphertext"), "Vault ciphertext");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> write(String path, Map<String, String> body) {
        try {
            var result = vault.post()
                .uri(path)
                .header(VAULT_TOKEN_HEADER, token())
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .body(body)
                .retrieve()
                .body(Map.class);
            if (result == null) throw new IdentityProtectionUnavailable("Vault returned an empty response");
            return (Map<String, Object>) result;
        } catch (RestClientException unavailable) {
            throw new IdentityProtectionUnavailable("Vault Transit is unavailable", unavailable);
        }
    }

    @SuppressWarnings("unchecked")
    private static String requireDataValue(Map<String, Object> response, String name) {
        var data = response.get("data");
        if (!(data instanceof Map<?, ?> raw)) {
            throw new IdentityProtectionUnavailable("Vault response omitted data");
        }
        var value = ((Map<String, Object>) raw).get(name);
        if (!(value instanceof String string) || string.isBlank()) {
            throw new IdentityProtectionUnavailable("Vault response omitted " + name);
        }
        return string;
    }

    private String token() {
        if (!tokenFile.isBlank()) {
            try {
                var value = Files.readString(Path.of(tokenFile), StandardCharsets.UTF_8).trim();
                if (!value.isBlank()) return value;
            } catch (IOException unreadable) {
                throw new IdentityProtectionUnavailable("Vault token file is unavailable", unreadable);
            }
        }
        if (!configuredToken.isBlank()) return configuredToken;
        throw new IdentityProtectionUnavailable("Vault authentication is not configured");
    }

    private static ProtectedValue versioned(String value, String label) {
        var parts = value.split(":", 3);
        if (parts.length != 3 || !"vault".equals(parts[0]) || !parts[1].startsWith("v")) {
            throw new IdentityProtectionUnavailable(label + " has an unsupported format");
        }
        try {
            var version = Integer.parseInt(parts[1].substring(1));
            if (version <= 0) throw new NumberFormatException("non-positive version");
            return new ProtectedValue(value, version);
        } catch (NumberFormatException invalid) {
            throw new IdentityProtectionUnavailable(label + " has an invalid key version", invalid);
        }
    }

    private static String cccdInput(String normalizedCccd) {
        if (normalizedCccd == null || !normalizedCccd.matches("^[0-9]{12}$")) {
            throw new IllegalArgumentException("CCCD must contain exactly 12 digits");
        }
        return "VN:CCCD:v1:" + normalizedCccd;
    }

    private static String requireValue(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(label + " is required");
        return value;
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String pathSegment(String value, String label) {
        var normalized = value == null ? "" : value.trim();
        if (!normalized.matches("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$")) {
            throw new IllegalArgumentException("Invalid Vault " + label);
        }
        return normalized;
    }

    private static String withoutTrailingSlash(String value) {
        var normalized = value == null ? "" : value.trim();
        if (normalized.isBlank()) throw new IllegalArgumentException("Vault address is required");
        return normalized.endsWith("/") ? normalized.substring(0, normalized.length() - 1) : normalized;
    }

    public static final class IdentityProtectionUnavailable extends RuntimeException {
        public IdentityProtectionUnavailable(String message) { super(message); }
        public IdentityProtectionUnavailable(String message, Throwable cause) { super(message, cause); }
    }
}
