package com.danyastry.encryption.core.stream;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.kdf.Argon2idParameters;
import com.danyastry.encryption.core.kdf.KdfAlgorithm;
import com.danyastry.encryption.core.kdf.KdfParameters;
import com.danyastry.encryption.core.kdf.Pbkdf2Parameters;
import com.danyastry.encryption.core.password.PasswordEnvelope;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

public record PasswordStreamHeader(KdfParameters kdf, byte[] salt, byte[] payloadNonce) {

    public static final int TYPE_PASSWORD_STREAM = 0x04;

    public PasswordStreamHeader {
        if (salt.length != PasswordEnvelope.SALT_LENGTH || payloadNonce.length != StreamChunks.PAYLOAD_NONCE_LENGTH) {
            throw new IllegalArgumentException("Salt or payload nonce has the wrong length");
        }
        salt = salt.clone();
        payloadNonce = payloadNonce.clone();
    }

    public byte[] encode() {
        int parameters = kdf instanceof Argon2idParameters ? 9 : 4;
        ByteBuffer buffer = ByteBuffer.allocate(PasswordEnvelope.MAGIC.length + 3 + parameters + salt.length + payloadNonce.length)
                .put(PasswordEnvelope.MAGIC)
                .put((byte) PasswordEnvelope.VERSION)
                .put((byte) TYPE_PASSWORD_STREAM)
                .put((byte) kdf.algorithm().id());
        if (kdf instanceof Pbkdf2Parameters pbkdf2) {
            buffer.putInt(pbkdf2.iterations());
        } else if (kdf instanceof Argon2idParameters argon2) {
            buffer.putInt(argon2.memoryKiB()).putInt(argon2.iterations()).put((byte) argon2.parallelism());
        }
        return buffer.put(salt).put(payloadNonce).array();
    }

    public static PasswordStreamHeader read(InputStream in) throws DecryptionException, IOException {
        DataInputStream data = new DataInputStream(in);
        try {
            byte[] magic = new byte[PasswordEnvelope.MAGIC.length];
            data.readFully(magic);
            if (!Arrays.equals(magic, PasswordEnvelope.MAGIC)) {
                throw new DecryptionException(DecryptionFailure.NOT_AN_ENVELOPE);
            }
            if (data.readUnsignedByte() != PasswordEnvelope.VERSION) {
                throw new DecryptionException(DecryptionFailure.UNSUPPORTED_VERSION);
            }
            if (data.readUnsignedByte() != TYPE_PASSWORD_STREAM) {
                throw new DecryptionException(DecryptionFailure.WRONG_TYPE);
            }
            KdfParameters kdf = switch (KdfAlgorithm.of(data.readUnsignedByte())) {
                case PBKDF2_HMAC_SHA256 -> new Pbkdf2Parameters(data.readInt());
                case ARGON2ID -> new Argon2idParameters(data.readInt(), data.readInt(), data.readUnsignedByte());
            };
            byte[] salt = new byte[PasswordEnvelope.SALT_LENGTH];
            byte[] nonce = new byte[StreamChunks.PAYLOAD_NONCE_LENGTH];
            data.readFully(salt);
            data.readFully(nonce);
            return new PasswordStreamHeader(kdf, salt, nonce);
        } catch (EOFException | IllegalArgumentException e) {
            throw new DecryptionException(DecryptionFailure.MALFORMED);
        }
    }

    @Override
    public byte[] salt() {
        return salt.clone();
    }

    @Override
    public byte[] payloadNonce() {
        return payloadNonce.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PasswordStreamHeader header && kdf.equals(header.kdf) && Arrays.equals(salt, header.salt)
                && Arrays.equals(payloadNonce, header.payloadNonce);
    }

    @Override
    public int hashCode() {
        return 31 * kdf.hashCode() + Arrays.hashCode(salt);
    }

    @Override
    public String toString() {
        return "PasswordStreamHeader[" + kdf + "]";
    }
}
