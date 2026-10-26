package com.danyastry.encryption.core.aead;

import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcm {

    public static final int KEY_LENGTH = 32;
    public static final int NONCE_LENGTH = 12;
    public static final int TAG_LENGTH = 16;

    private AesGcm() {
    }

    public static byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        try {
            return cipher(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM is not available", e);
        }
    }

    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) throws AEADBadTagException {
        try {
            return cipher(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM is not available", e);
        }
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("AES-256 needs a " + KEY_LENGTH + "-byte key, got " + key.length);
        }
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("GCM nonces are " + NONCE_LENGTH + " bytes, got " + nonce.length);
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH * 8, nonce));
        cipher.updateAAD(aad);
        return cipher;
    }
}
