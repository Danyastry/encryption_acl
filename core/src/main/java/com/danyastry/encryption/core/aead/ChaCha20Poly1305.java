package com.danyastry.encryption.core.aead;

import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class ChaCha20Poly1305 {

    public static final int KEY_LENGTH = 32;
    public static final int NONCE_LENGTH = 12;
    public static final int TAG_LENGTH = 16;

    private ChaCha20Poly1305() {
    }

    public static byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        try {
            return cipher(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20-Poly1305 is not available", e);
        }
    }

    public static byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) throws AEADBadTagException {
        try {
            return cipher(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20-Poly1305 is not available", e);
        }
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        if (key.length != KEY_LENGTH || nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("ChaCha20-Poly1305 needs a 32-byte key and a 12-byte nonce");
        }
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        cipher.updateAAD(aad);
        return cipher;
    }
}
