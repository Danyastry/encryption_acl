package com.danyastry.encryption.cli;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.keys.KeyFileException;
import com.danyastry.encryption.core.signature.VerificationException;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import picocli.CommandLine;
import picocli.CommandLine.IExecutionExceptionHandler;
import picocli.CommandLine.ParseResult;

final class ErrorHandler implements IExecutionExceptionHandler {

    static final int FAILURE = 1;

    @Override
    public int handleExecutionException(Exception error, CommandLine command, ParseResult parseResult) throws Exception {
        String message;
        if (error instanceof NoSuchFileException missing) {
            message = "No such file: " + missing.getFile();
        } else if (error instanceof DecryptionException || error instanceof VerificationException
                || error instanceof KeyFileException || error instanceof IllegalArgumentException || error instanceof IOException) {
            message = error.getMessage();
        } else {
            throw error;
        }
        command.getErr().println("error: " + message);
        command.getErr().flush();
        return FAILURE;
    }
}
