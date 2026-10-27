package com.danyastry.encryption.core.password;

import com.danyastry.encryption.core.aead.AesGcm;
import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.kdf.Argon2idParameters;
import com.danyastry.encryption.core.kdf.KdfAlgorithm;
import com.danyastry.encryption.core.kdf.KdfParameters;
import com.danyastry.encryption.core.kdf.Pbkdf2Parameters;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public record PasswordEnvelope(KdfParameters kdf, byte[] salt, byte[] nonce, byte[] ciphertext) {

    public static final byte[] MAGIC = "EACL".getBytes(StandardCharsets.US_ASCII);
    public static final int VERSION = 1;
    public static final int TYPE_PASSWORD = 0x01;
    public static final int SALT_LENGTH = 16;

    public PasswordEnvelope {
        if (salt.length != SALT_LENGTH || nonce.length != AesGcm.NONCE_LENGTH || ciphertext.length < AesGcm.TAG_LENGTH) {
            throw new IllegalArgumentException("Salt, nonce or ciphertext has the wrong length");
        }
        salt = salt.clone();
        nonce = nonce.clone();
        ciphertext = ciphertext.clone();
    }

    public byte[] header() {
        ByteBuffer buffer = ByteBuffer.allocate(headerLength(kdf));
        buffer.put(MAGIC).put((byte) VERSION).put((byte) TYPE_PASSWORD).put((byte) kdf.algorithm().id());
        if (kdf instanceof Pbkdf2Parameters pbkdf2) {
            buffer.putInt(pbkdf2.iterations());
        } else if (kdf instanceof Argon2idParameters argon2) {
            buffer.putInt(argon2.memoryKiB()).putInt(argon2.iterations()).put((byte) argon2.parallelism());
        }
        return buffer.put(salt).put(nonce).array();
    }

    public byte[] encode() {
        byte[] header = header();
        byte[] out = Arrays.copyOf(header, header.length + ciphertext.length);
        System.arraycopy(ciphertext, 0, out, header.length, ciphertext.length);
        return out;
    }

    public static PasswordEnvelope parse(byte[] bytes) throws DecryptionException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        try {
            byte[] magic = new byte[MAGIC.length];
            buffer.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new DecryptionException(DecryptionFailure.NOT_AN_ENVELOPE);
            }
            int version = buffer.get() & 0xFF;
            if (version != VERSION) {
                throw new DecryptionException(DecryptionFailure.UNSUPPORTED_VERSION);
            }
            if ((buffer.get() & 0xFF) != TYPE_PASSWORD) {
                throw new DecryptionException(DecryptionFailure.WRONG_TYPE);
            }
            KdfParameters kdf = readKdf(buffer);
            byte[] salt = new byte[SALT_LENGTH];
            byte[] nonce = new byte[AesGcm.NONCE_LENGTH];
            buffer.get(salt).get(nonce);
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);
            return new PasswordEnvelope(kdf, salt, nonce, ciphertext);
        } catch (BufferUnderflowException | IllegalArgumentException e) {
            throw new DecryptionException(DecryptionFailure.MALFORMED);
        }
    }

    private static KdfParameters readKdf(ByteBuffer buffer) {
        return switch (KdfAlgorithm.of(buffer.get() & 0xFF)) {
            case PBKDF2_HMAC_SHA256 -> new Pbkdf2Parameters(buffer.getInt());
            case ARGON2ID -> new Argon2idParameters(buffer.getInt(), buffer.getInt(), buffer.get() & 0xFF);
        };
    }

    private static int headerLength(KdfParameters kdf) {
        int parameters = switch (kdf.algorithm()) {
            case PBKDF2_HMAC_SHA256 -> 4;
            case ARGON2ID -> 9;
        };
        return MAGIC.length + 3 + parameters + SALT_LENGTH + AesGcm.NONCE_LENGTH;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PasswordEnvelope envelope && kdf.equals(envelope.kdf) && Arrays.equals(salt, envelope.salt)
                && Arrays.equals(nonce, envelope.nonce) && Arrays.equals(ciphertext, envelope.ciphertext);
    }

    @Override
    public int hashCode() {
        return 31 * kdf.hashCode() + Arrays.hashCode(ciphertext);
    }

    @Override
    public String toString() {
        return "PasswordEnvelope[" + kdf + ", " + ciphertext.length + " bytes]";
    }
}
