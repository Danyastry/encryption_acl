package com.danyastry.encryption.core.stream;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.kdf.Argon2idParameters;
import com.danyastry.encryption.core.kdf.KdfParameters;
import com.danyastry.encryption.core.password.PasswordEnvelope;
import com.danyastry.encryption.core.util.Secrets;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public final class PasswordFileEncryption {

    private static final int COPY_BUFFER = 16 * 1024;

    private final KdfParameters kdf;
    private final SecureRandom random;

    public PasswordFileEncryption(KdfParameters kdf, SecureRandom random) {
        this.kdf = kdf;
        this.random = random;
    }

    public PasswordFileEncryption(KdfParameters kdf) {
        this(kdf, new SecureRandom());
    }

    public static PasswordFileEncryption recommended() {
        return new PasswordFileEncryption(Argon2idParameters.recommended());
    }

    public long encrypt(InputStream in, OutputStream out, char[] password) throws IOException {
        byte[] salt = new byte[PasswordEnvelope.SALT_LENGTH];
        byte[] nonce = new byte[StreamChunks.PAYLOAD_NONCE_LENGTH];
        random.nextBytes(salt);
        random.nextBytes(nonce);
        byte[] header = new PasswordStreamHeader(kdf, salt, nonce).encode();
        out.write(header);
        byte[] payloadKey = payloadKey(kdf, password, salt, nonce, header);
        EncryptingOutputStream sealed = new EncryptingOutputStream(out, payloadKey);
        Secrets.wipe(payloadKey);
        long total = in.transferTo(sealed);
        sealed.finish();
        return total;
    }

    public static long decrypt(InputStream in, OutputStream out, char[] password) throws IOException, DecryptionException {
        InputStream plaintext = open(in, password);
        try {
            byte[] buffer = new byte[COPY_BUFFER];
            long total = 0;
            for (int count; (count = plaintext.read(buffer)) != -1; total += count) {
                out.write(buffer, 0, count);
            }
            return total;
        } catch (StreamDecryptionException e) {
            throw new DecryptionException(e.failure());
        }
    }

    public static InputStream open(InputStream in, char[] password) throws IOException, DecryptionException {
        PasswordStreamHeader header = PasswordStreamHeader.read(in);
        byte[] payloadKey = payloadKey(header.kdf(), password, header.salt(), header.payloadNonce(), header.encode());
        try {
            return new DecryptingInputStream(in, payloadKey, false);
        } finally {
            Secrets.wipe(payloadKey);
        }
    }

    private static byte[] payloadKey(KdfParameters kdf, char[] password, byte[] salt, byte[] nonce, byte[] header) {
        byte[] fileKey = kdf.derive(password, salt, 32);
        try {
            return StreamChunks.payloadKey(fileKey, nonce, header);
        } finally {
            Secrets.wipe(fileKey);
        }
    }
}
