package com.danyastry.encryption.core.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class Fingerprint {

    public static final int LENGTH = 8;

    private Fingerprint() {
    }

    public static String of(byte[] publicKey) {
        return format(bytes(publicKey));
    }

    public static byte[] bytes(byte[] publicKey) {
        try {
            return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(publicKey), LENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    public static String format(byte[] fingerprint) {
        return String.join(":", Hex.encode(fingerprint).split("(?<=\\G.{4})"));
    }
}
