package com.danyastry.encryption.core.error;

public enum DecryptionFailure {
    NOT_AN_ENVELOPE("The data is not an encryption_acl envelope"),
    UNSUPPORTED_VERSION("The envelope was made by a newer format version"),
    WRONG_TYPE("The envelope is of a different kind: password or public key"),
    MISSING_SENDER_KEY("The message is from an authenticated sender; give the sender's public key"),
    MALFORMED("The envelope is truncated or has invalid parameters"),
    AUTHENTICATION_FAILED("Wrong password, or the data was changed"),
    NOT_A_RECIPIENT("Your key is not one of the recipients of this file"),
    TRUNCATED("The data ends before its last chunk"),
    TRAILING_DATA("Extra data follows the end of the encrypted stream");

    private final String description;

    DecryptionFailure(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
