package com.danyastry.encryption.core.signature;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Signatures {

    private static final byte[] FILE_LABEL = "encryption_acl file sha512\0".getBytes(StandardCharsets.US_ASCII);

    private Signatures() {
    }

    public static byte[] sign(byte[] message, Ed25519KeyPair signer) {
        byte[] publicKey = signer.publicKey();
        byte[] signature = signer.sign(signedBytes(publicKey, message));
        return new SignatureEnvelope(publicKey, signature).encode();
    }

    public static SignatureEnvelope verify(byte[] message, byte[] envelopeBytes, byte[] trustedPublicKey) throws VerificationException {
        SignatureEnvelope envelope = SignatureEnvelope.parse(envelopeBytes);
        if (!MessageDigest.isEqual(envelope.signerPublicKey(), trustedPublicKey)) {
            throw new VerificationException(VerificationFailure.WRONG_SIGNER);
        }
        if (!Ed25519KeyPair.verify(trustedPublicKey, signedBytes(trustedPublicKey, message), envelope.signature())) {
            throw new VerificationException(VerificationFailure.INVALID_SIGNATURE);
        }
        return envelope;
    }

    public static byte[] signStream(InputStream in, Ed25519KeyPair signer) throws IOException {
        return sign(fileDigest(in), signer);
    }

    public static SignatureEnvelope verifyStream(InputStream in, byte[] envelopeBytes, byte[] trustedPublicKey)
            throws IOException, VerificationException {
        return verify(fileDigest(in), envelopeBytes, trustedPublicKey);
    }

    static byte[] fileDigest(InputStream in) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.update(FILE_LABEL);
            byte[] buffer = new byte[16 * 1024];
            for (int count; (count = in.read(buffer)) != -1; ) {
                digest.update(buffer, 0, count);
            }
            byte[] hash = digest.digest();
            byte[] out = new byte[FILE_LABEL.length + hash.length];
            System.arraycopy(FILE_LABEL, 0, out, 0, FILE_LABEL.length);
            System.arraycopy(hash, 0, out, FILE_LABEL.length, hash.length);
            return out;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 is not available", e);
        }
    }

    static byte[] signedBytes(byte[] publicKey, byte[] message) {
        byte[] header = SignatureEnvelope.header(publicKey);
        byte[] out = new byte[header.length + message.length];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(message, 0, out, header.length, message.length);
        return out;
    }
}
