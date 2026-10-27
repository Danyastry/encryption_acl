package com.danyastry.encryption.core.stream;

import com.danyastry.encryption.core.aead.ChaCha20Poly1305;
import com.danyastry.encryption.core.hpke.Hkdf;
import java.nio.charset.StandardCharsets;
import javax.crypto.AEADBadTagException;

public final class StreamChunks {

    public static final int CHUNK_SIZE = 64 * 1024;
    public static final int SEALED_CHUNK_SIZE = CHUNK_SIZE + ChaCha20Poly1305.TAG_LENGTH;
    public static final int PAYLOAD_NONCE_LENGTH = 16;

    private static final byte[] PAYLOAD_LABEL = "encryption_acl v1 payload".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] NO_AAD = new byte[0];

    private StreamChunks() {
    }

    public static byte[] payloadKey(byte[] fileKey, byte[] payloadNonce, byte[] header) {
        byte[] info = new byte[PAYLOAD_LABEL.length + header.length];
        System.arraycopy(PAYLOAD_LABEL, 0, info, 0, PAYLOAD_LABEL.length);
        System.arraycopy(header, 0, info, PAYLOAD_LABEL.length, header.length);
        return Hkdf.expand(Hkdf.extract(payloadNonce, fileKey), info, ChaCha20Poly1305.KEY_LENGTH);
    }

    static byte[] nonce(long counter, boolean last) {
        if (counter < 0) {
            throw new IllegalStateException("Chunk counter overflow");
        }
        byte[] nonce = new byte[ChaCha20Poly1305.NONCE_LENGTH];
        for (int i = 0; i < Long.BYTES; i++) {
            nonce[nonce.length - 2 - i] = (byte) (counter >>> (8 * i));
        }
        nonce[nonce.length - 1] = (byte) (last ? 1 : 0);
        return nonce;
    }

    static byte[] seal(byte[] key, long counter, boolean last, byte[] plaintext) {
        return ChaCha20Poly1305.seal(key, nonce(counter, last), NO_AAD, plaintext);
    }

    static byte[] open(byte[] key, long counter, boolean last, byte[] sealed) throws AEADBadTagException {
        return ChaCha20Poly1305.open(key, nonce(counter, last), NO_AAD, sealed);
    }
}
