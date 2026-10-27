package com.danyastry.encryption.core.keys;

import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.signature.Ed25519KeyPair;
import java.security.SecureRandom;

public record Identity(X25519KeyPair encryption, Ed25519KeyPair signing) {

    public static Identity generate(SecureRandom random) {
        return new Identity(X25519KeyPair.generate(random), Ed25519KeyPair.generate(random));
    }

    public PublicIdentity publicIdentity() {
        return new PublicIdentity(encryption.publicKey(), signing.publicKey());
    }

    public String fingerprint() {
        return publicIdentity().fingerprint();
    }

    @Override
    public String toString() {
        return "Identity[" + fingerprint() + "]";
    }
}
