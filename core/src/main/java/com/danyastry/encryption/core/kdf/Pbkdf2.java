package com.danyastry.encryption.core.kdf;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class Pbkdf2 {

    private Pbkdf2() {
    }

    public static byte[] deriveSha256(char[] password, byte[] salt, int iterations, int length) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, length * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2-HMAC-SHA256 is not available", e);
        } finally {
            spec.clearPassword();
        }
    }
}
