package com.danyastry.encryption.core.password;

import com.danyastry.encryption.core.aead.AesGcm;
import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.kdf.Argon2idParameters;
import com.danyastry.encryption.core.kdf.KdfParameters;
import com.danyastry.encryption.core.util.Secrets;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;

public final class PasswordEncryption {

    private final KdfParameters kdf;
    private final SecureRandom random;

    public PasswordEncryption(KdfParameters kdf, SecureRandom random) {
        this.kdf = kdf;
        this.random = random;
    }

    public PasswordEncryption(KdfParameters kdf) {
        this(kdf, new SecureRandom());
    }

    public static PasswordEncryption recommended() {
        return new PasswordEncryption(Argon2idParameters.recommended());
    }

    public KdfParameters kdf() {
        return kdf;
    }

    public byte[] encrypt(byte[] plaintext, char[] password) {
        byte[] salt = new byte[PasswordEnvelope.SALT_LENGTH];
        byte[] nonce = new byte[AesGcm.NONCE_LENGTH];
        random.nextBytes(salt);
        random.nextBytes(nonce);
        byte[] header = new PasswordEnvelope(kdf, salt, nonce, new byte[AesGcm.TAG_LENGTH]).header();
        byte[] key = kdf.derive(password, salt, AesGcm.KEY_LENGTH);
        try {
            return new PasswordEnvelope(kdf, salt, nonce, AesGcm.encrypt(key, nonce, header, plaintext)).encode();
        } finally {
            Secrets.wipe(key);
        }
    }

    public static byte[] decrypt(byte[] envelopeBytes, char[] password) throws DecryptionException {
        PasswordEnvelope envelope = PasswordEnvelope.parse(envelopeBytes);
        byte[] key = envelope.kdf().derive(password, envelope.salt(), AesGcm.KEY_LENGTH);
        try {
            return AesGcm.decrypt(key, envelope.nonce(), envelope.header(), envelope.ciphertext());
        } catch (AEADBadTagException e) {
            throw new DecryptionException(DecryptionFailure.AUTHENTICATION_FAILED);
        } finally {
            Secrets.wipe(key);
        }
    }
}
