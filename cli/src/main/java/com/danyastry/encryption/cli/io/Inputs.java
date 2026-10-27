package com.danyastry.encryption.cli.io;

import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Inputs {

    private Inputs() {
    }

    public static InputStream open(Path file, InputStream standardInput) throws IOException {
        if (file == null) {
            return new BufferedInputStream(new FilterInputStream(standardInput) {
                @Override
                public void close() {
                }
            });
        }
        return new BufferedInputStream(Files.newInputStream(file));
    }

    public static String text(Path file) throws IOException {
        return Files.readString(file, StandardCharsets.UTF_8);
    }

    public static int peekType(InputStream in) throws IOException {
        in.mark(8);
        byte[] header = in.readNBytes(6);
        in.reset();
        return header.length == 6 ? header[5] & 0xFF : -1;
    }
}
