package com.danyastry.encryption.core.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class Fingerprint {

    public static final int LENGTH = 8;

    private Fingerprint() {
    }

    public static String of(byte[] publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey);
            String hex = Hex.encode(Arrays.copyOf(digest, LENGTH));
            return String.join(":", hex.split("(?<=\\G.{4})"));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
