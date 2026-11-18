package com.vistay.user.application;

/**
 * Purpose-scoped protection for national identifiers and link challenges.
 * Implementations must never log plaintext inputs or return a reusable key.
 */
public interface IdentityProtection {
    ProtectedDocument protectIdentityDocument(
        String documentCountry,
        String documentType,
        String normalizedValue
    );

    ProtectedValue hmacIdentityDocument(
        String documentCountry,
        String documentType,
        String normalizedValue
    );

    default ProtectedDocument protectCccd(String normalizedCccd) {
        return protectIdentityDocument("VN", "CCCD", normalizedCccd);
    }

    default ProtectedValue hmacCccd(String normalizedCccd) {
        return hmacIdentityDocument("VN", "CCCD", normalizedCccd);
    }

    ProtectedValue hmacOtpEvidence(String canonicalEvidence);

    ProtectedValue encryptOtpDelivery(String canonicalDeliverySecret);

    record ProtectedDocument(
        String lookupHmac,
        int lookupKeyVersion,
        String ciphertext,
        int encryptionKeyVersion
    ) {}

    record ProtectedValue(String value, int keyVersion) {}
}
