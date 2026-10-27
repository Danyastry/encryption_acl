package com.danyastry.encryption.core.hpke;

import com.danyastry.encryption.core.aead.ChaCha20Poly1305;
import javax.crypto.AEADBadTagException;

public final class HpkeContext {

    private final byte[] key;
    private final byte[] baseNonce;
    private final byte[] exporterSecret;
    private final LabeledKdf kdf;
    private long sequence;

    HpkeContext(byte[] key, byte[] baseNonce, byte[] exporterSecret, LabeledKdf kdf) {
        this.key = key;
        this.baseNonce = baseNonce;
        this.exporterSecret = exporterSecret;
        this.kdf = kdf;
    }

    public byte[] key() {
        return key.clone();
    }

    public byte[] baseNonce() {
        return baseNonce.clone();
    }

    public byte[] exporterSecret() {
        return exporterSecret.clone();
    }

    public synchronized byte[] seal(byte[] aad, byte[] plaintext) {
        byte[] ciphertext = ChaCha20Poly1305.seal(key, nextNonce(), aad, plaintext);
        sequence++;
        return ciphertext;
    }

    public synchronized byte[] open(byte[] aad, byte[] ciphertext) throws AEADBadTagException {
        byte[] plaintext = ChaCha20Poly1305.open(key, nextNonce(), aad, ciphertext);
        sequence++;
        return plaintext;
    }

    public byte[] export(byte[] context, int length) {
        return kdf.expand(exporterSecret, "sec", context, length);
    }

    private byte[] nextNonce() {
        if (sequence == Long.MAX_VALUE) {
            throw new IllegalStateException("HPKE sequence number overflow");
        }
        byte[] nonce = baseNonce.clone();
        for (int i = 0; i < Long.BYTES; i++) {
            nonce[nonce.length - 1 - i] ^= (byte) (sequence >>> (8 * i));
        }
        return nonce;
    }
}
