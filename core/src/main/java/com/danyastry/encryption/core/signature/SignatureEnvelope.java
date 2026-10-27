package com.danyastry.encryption.core.signature;

import com.danyastry.encryption.core.password.PasswordEnvelope;
import com.danyastry.encryption.core.util.Fingerprint;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public record SignatureEnvelope(byte[] signerPublicKey, byte[] signature) {

    public static final int TYPE_SIGNATURE = 0x03;
    public static final int ALGORITHM_ED25519 = 0x01;
    public static final int SIGNATURE_LENGTH = 64;
    public static final int HEADER_LENGTH = PasswordEnvelope.MAGIC.length + 3 + Ed25519KeyPair.KEY_LENGTH;
    public static final int LENGTH = HEADER_LENGTH + SIGNATURE_LENGTH;

    public SignatureEnvelope {
        if (signerPublicKey.length != Ed25519KeyPair.KEY_LENGTH || signature.length != SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("Signer key or signature has the wrong length");
        }
        signerPublicKey = signerPublicKey.clone();
        signature = signature.clone();
    }

    public static byte[] header(byte[] signerPublicKey) {
        return ByteBuffer.allocate(HEADER_LENGTH)
                .put(PasswordEnvelope.MAGIC)
                .put((byte) PasswordEnvelope.VERSION)
                .put((byte) TYPE_SIGNATURE)
                .put((byte) ALGORITHM_ED25519)
                .put(signerPublicKey)
                .array();
    }

    public byte[] encode() {
        byte[] out = Arrays.copyOf(header(signerPublicKey), LENGTH);
        System.arraycopy(signature, 0, out, HEADER_LENGTH, SIGNATURE_LENGTH);
        return out;
    }

    public static SignatureEnvelope parse(byte[] bytes) throws VerificationException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        try {
            byte[] magic = new byte[PasswordEnvelope.MAGIC.length];
            buffer.get(magic);
            if (!Arrays.equals(magic, PasswordEnvelope.MAGIC)) {
                throw new VerificationException(VerificationFailure.NOT_A_SIGNATURE);
            }
            if ((buffer.get() & 0xFF) != PasswordEnvelope.VERSION) {
                throw new VerificationException(VerificationFailure.UNSUPPORTED_VERSION);
            }
            if ((buffer.get() & 0xFF) != TYPE_SIGNATURE) {
                throw new VerificationException(VerificationFailure.NOT_A_SIGNATURE);
            }
            if ((buffer.get() & 0xFF) != ALGORITHM_ED25519 || bytes.length != LENGTH) {
                throw new VerificationException(VerificationFailure.MALFORMED);
            }
            byte[] key = new byte[Ed25519KeyPair.KEY_LENGTH];
            byte[] signature = new byte[SIGNATURE_LENGTH];
            buffer.get(key).get(signature);
            return new SignatureEnvelope(key, signature);
        } catch (BufferUnderflowException e) {
            throw new VerificationException(VerificationFailure.MALFORMED);
        }
    }

    @Override
    public byte[] signerPublicKey() {
        return signerPublicKey.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SignatureEnvelope envelope && Arrays.equals(signerPublicKey, envelope.signerPublicKey)
                && Arrays.equals(signature, envelope.signature);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(signerPublicKey) + Arrays.hashCode(signature);
    }

    @Override
    public String toString() {
        return "SignatureEnvelope[signer=" + Fingerprint.of(signerPublicKey) + "]";
    }
}
