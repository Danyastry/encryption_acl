package com.danyastry.encryption.core.keys;

import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.signature.Ed25519KeyPair;
import com.danyastry.encryption.core.util.Fingerprint;
import java.util.Arrays;

public record PublicIdentity(byte[] encryptionKey, byte[] signingKey) {

    public PublicIdentity {
        if (encryptionKey.length != X25519KeyPair.KEY_LENGTH || signingKey.length != Ed25519KeyPair.KEY_LENGTH) {
            throw new IllegalArgumentException("Public identity needs a 32-byte X25519 key and a 32-byte Ed25519 key");
        }
        encryptionKey = encryptionKey.clone();
        signingKey = signingKey.clone();
    }

    public String fingerprint() {
        return Fingerprint.of(encryptionKey);
    }

    public String signingFingerprint() {
        return Fingerprint.of(signingKey);
    }

    @Override
    public byte[] encryptionKey() {
        return encryptionKey.clone();
    }

    @Override
    public byte[] signingKey() {
        return signingKey.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PublicIdentity identity && Arrays.equals(encryptionKey, identity.encryptionKey)
                && Arrays.equals(signingKey, identity.signingKey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encryptionKey);
    }

    @Override
    public String toString() {
        return "PublicIdentity[" + fingerprint() + "]";
    }
}
