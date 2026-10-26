package com.danyastry.encryption.core.password;

public enum DecryptionFailure {
    NOT_AN_ENVELOPE("The data is not an encryption_acl envelope"),
    UNSUPPORTED_VERSION("The envelope was made by a newer format version"),
    WRONG_TYPE("The envelope was not made with a password"),
    MALFORMED("The envelope is truncated or has invalid parameters"),
    AUTHENTICATION_FAILED("Wrong password, or the data was changed");

    private final String description;

    DecryptionFailure(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
