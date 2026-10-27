package com.danyastry.encryption.core.signature;

import java.security.MessageDigest;

public final class Signatures {

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

    static byte[] signedBytes(byte[] publicKey, byte[] message) {
        byte[] header = SignatureEnvelope.header(publicKey);
        byte[] out = new byte[header.length + message.length];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(message, 0, out, header.length, message.length);
        return out;
    }
}
