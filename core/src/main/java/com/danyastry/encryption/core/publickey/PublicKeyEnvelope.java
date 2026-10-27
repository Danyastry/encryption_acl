package com.danyastry.encryption.core.publickey;

import com.danyastry.encryption.core.aead.ChaCha20Poly1305;
import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.hpke.Hpke;
import com.danyastry.encryption.core.hpke.HpkeMode;
import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.password.PasswordEnvelope;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public record PublicKeyEnvelope(HpkeMode mode, byte[] enc, byte[] ciphertext) {

    public static final int TYPE_PUBLIC_KEY = 0x02;
    public static final int HEADER_LENGTH = PasswordEnvelope.MAGIC.length + 3 + Hpke.SUITE.length + X25519KeyPair.KEY_LENGTH;

    public PublicKeyEnvelope {
        if (enc.length != X25519KeyPair.KEY_LENGTH || ciphertext.length < ChaCha20Poly1305.TAG_LENGTH) {
            throw new IllegalArgumentException("Encapsulated key or ciphertext has the wrong length");
        }
        enc = enc.clone();
        ciphertext = ciphertext.clone();
    }

    public byte[] header() {
        return ByteBuffer.allocate(HEADER_LENGTH)
                .put(PasswordEnvelope.MAGIC)
                .put((byte) PasswordEnvelope.VERSION)
                .put((byte) TYPE_PUBLIC_KEY)
                .put((byte) mode.id())
                .put(Hpke.SUITE)
                .put(enc)
                .array();
    }

    public byte[] encode() {
        byte[] header = header();
        byte[] out = Arrays.copyOf(header, header.length + ciphertext.length);
        System.arraycopy(ciphertext, 0, out, header.length, ciphertext.length);
        return out;
    }

    public static PublicKeyEnvelope parse(byte[] bytes) throws DecryptionException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        try {
            byte[] magic = new byte[PasswordEnvelope.MAGIC.length];
            buffer.get(magic);
            if (!Arrays.equals(magic, PasswordEnvelope.MAGIC)) {
                throw new DecryptionException(DecryptionFailure.NOT_AN_ENVELOPE);
            }
            if ((buffer.get() & 0xFF) != PasswordEnvelope.VERSION) {
                throw new DecryptionException(DecryptionFailure.UNSUPPORTED_VERSION);
            }
            if ((buffer.get() & 0xFF) != TYPE_PUBLIC_KEY) {
                throw new DecryptionException(DecryptionFailure.WRONG_TYPE);
            }
            HpkeMode mode = HpkeMode.of(buffer.get() & 0xFF);
            byte[] suite = new byte[Hpke.SUITE.length];
            buffer.get(suite);
            if (!Arrays.equals(suite, Hpke.SUITE)) {
                throw new DecryptionException(DecryptionFailure.MALFORMED);
            }
            byte[] enc = new byte[X25519KeyPair.KEY_LENGTH];
            buffer.get(enc);
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);
            return new PublicKeyEnvelope(mode, enc, ciphertext);
        } catch (BufferUnderflowException | IllegalArgumentException e) {
            throw new DecryptionException(DecryptionFailure.MALFORMED);
        }
    }

    @Override
    public byte[] enc() {
        return enc.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PublicKeyEnvelope envelope && mode == envelope.mode && Arrays.equals(enc, envelope.enc)
                && Arrays.equals(ciphertext, envelope.ciphertext);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(enc) + Arrays.hashCode(ciphertext);
    }

    @Override
    public String toString() {
        return "PublicKeyEnvelope[" + mode + ", " + ciphertext.length + " bytes]";
    }
}
