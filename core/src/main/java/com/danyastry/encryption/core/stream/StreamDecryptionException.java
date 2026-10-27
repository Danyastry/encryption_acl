package com.danyastry.encryption.core.stream;

import com.danyastry.encryption.core.error.DecryptionFailure;
import java.io.IOException;

public final class StreamDecryptionException extends IOException {

    private static final long serialVersionUID = 1L;

    private final DecryptionFailure failure;

    public StreamDecryptionException(DecryptionFailure failure) {
        super(failure.description());
        this.failure = failure;
    }

    public DecryptionFailure failure() {
        return failure;
    }
}
