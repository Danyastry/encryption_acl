package com.danyastry.encryption.core.acl;

import com.danyastry.encryption.core.aead.ChaCha20Poly1305;
import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.util.Fingerprint;
import java.util.Arrays;

public record RecipientStanza(byte[] fingerprint, byte[] enc, byte[] wrappedFileKey) {

    public static final int WRAPPED_KEY_LENGTH = RecipientFiles.FILE_KEY_LENGTH + ChaCha20Poly1305.TAG_LENGTH;
    public static final int LENGTH = Fingerprint.LENGTH + X25519KeyPair.KEY_LENGTH + WRAPPED_KEY_LENGTH;

    public RecipientStanza {
        if (fingerprint.length != Fingerprint.LENGTH || enc.length != X25519KeyPair.KEY_LENGTH || wrappedFileKey.length != WRAPPED_KEY_LENGTH) {
            throw new IllegalArgumentException("Recipient stanza has the wrong length");
        }
        fingerprint = fingerprint.clone();
        enc = enc.clone();
        wrappedFileKey = wrappedFileKey.clone();
    }

    @Override
    public byte[] fingerprint() {
        return fingerprint.clone();
    }

    @Override
    public byte[] enc() {
        return enc.clone();
    }

    @Override
    public byte[] wrappedFileKey() {
        return wrappedFileKey.clone();
    }

    public boolean isFor(byte[] otherFingerprint) {
        return Arrays.equals(fingerprint, otherFingerprint);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof RecipientStanza stanza && Arrays.equals(fingerprint, stanza.fingerprint)
                && Arrays.equals(enc, stanza.enc) && Arrays.equals(wrappedFileKey, stanza.wrappedFileKey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(fingerprint);
    }

    @Override
    public String toString() {
        return "RecipientStanza[" + Fingerprint.format(fingerprint) + "]";
    }
}
