package com.danyastry.encryption.core.signature;

public final class VerificationException extends Exception {

    private static final long serialVersionUID = 1L;

    private final VerificationFailure failure;

    public VerificationException(VerificationFailure failure) {
        super(failure.description());
        this.failure = failure;
    }

    public VerificationFailure failure() {
        return failure;
    }
}
