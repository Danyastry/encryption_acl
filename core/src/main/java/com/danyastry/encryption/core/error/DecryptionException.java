package com.danyastry.encryption.core.error;

public final class DecryptionException extends Exception {

    private static final long serialVersionUID = 1L;

    private final DecryptionFailure failure;

    public DecryptionException(DecryptionFailure failure) {
        super(failure.description());
        this.failure = failure;
    }

    public DecryptionFailure failure() {
        return failure;
    }
}
