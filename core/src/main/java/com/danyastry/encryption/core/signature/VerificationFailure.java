package com.danyastry.encryption.core.signature;

public enum VerificationFailure {
    NOT_A_SIGNATURE("The data is not an encryption_acl signature"),
    UNSUPPORTED_VERSION("The signature was made by a newer format version"),
    MALFORMED("The signature is truncated or uses an unknown algorithm"),
    WRONG_SIGNER("The signature was made by a different key than the one you trust"),
    INVALID_SIGNATURE("The signature does not match the data");

    private final String description;

    VerificationFailure(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
