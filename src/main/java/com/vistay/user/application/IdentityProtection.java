package com.vistay.user.application;

/**
 * Purpose-scoped protection for national identifiers and link challenges.
 * Implementations must never log plaintext inputs or return a reusable key.
 */
public interface IdentityProtection {
    ProtectedDocument protectCccd(String normalizedCccd);

    ProtectedValue hmacCccd(String normalizedCccd);

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
