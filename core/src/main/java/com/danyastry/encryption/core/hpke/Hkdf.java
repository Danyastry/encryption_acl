package com.danyastry.encryption.core.hpke;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Hkdf {

    public static final int HASH_LENGTH = 32;

    private Hkdf() {
    }

    public static byte[] extract(byte[] salt, byte[] ikm) {
        return hmac(salt.length == 0 ? new byte[HASH_LENGTH] : salt, ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (length < 0 || length > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException("HKDF-SHA256 can expand to at most " + 255 * HASH_LENGTH + " bytes");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(length);
        byte[] block = new byte[0];
        for (int counter = 1; out.size() < length; counter++) {
            byte[] input = new byte[block.length + info.length + 1];
            System.arraycopy(block, 0, input, 0, block.length);
            System.arraycopy(info, 0, input, block.length, info.length);
            input[input.length - 1] = (byte) counter;
            block = hmac(prk, input);
            out.write(block, 0, Math.min(block.length, length - out.size()));
        }
        return out.toByteArray();
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }
}
