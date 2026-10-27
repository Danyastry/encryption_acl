package com.danyastry.encryption.core.legacy;

import com.danyastry.encryption.core.aead.AesGcm;
import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.kdf.Pbkdf2;
import com.danyastry.encryption.core.util.Secrets;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.AEADBadTagException;

public final class LegacyStandardFormat {

    public static final int ITERATIONS = 65_536;
    private static final int SALT_LENGTH = 16;

    private LegacyStandardFormat() {
    }

    public static byte[] decrypt(String base64, char[] password) throws DecryptionException {
        byte[] data;
        try {
            data = Base64.getDecoder().decode(base64.trim());
        } catch (IllegalArgumentException e) {
            throw new DecryptionException(DecryptionFailure.MALFORMED);
        }
        if (data.length < SALT_LENGTH + AesGcm.NONCE_LENGTH + AesGcm.TAG_LENGTH) {
            throw new DecryptionException(DecryptionFailure.MALFORMED);
        }
        byte[] salt = Arrays.copyOfRange(data, 0, SALT_LENGTH);
        byte[] nonce = Arrays.copyOfRange(data, SALT_LENGTH, SALT_LENGTH + AesGcm.NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(data, SALT_LENGTH + AesGcm.NONCE_LENGTH, data.length);
        byte[] key = Pbkdf2.deriveSha256(password, salt, ITERATIONS, AesGcm.KEY_LENGTH);
        try {
            return AesGcm.decrypt(key, nonce, salt, ciphertext);
        } catch (AEADBadTagException e) {
            throw new DecryptionException(DecryptionFailure.AUTHENTICATION_FAILED);
        } finally {
            Secrets.wipe(key);
        }
    }
}
