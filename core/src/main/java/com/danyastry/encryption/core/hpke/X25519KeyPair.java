package com.danyastry.encryption.core.hpke;

import com.danyastry.encryption.core.util.Hex;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.math.ec.rfc7748.X25519;

public record X25519KeyPair(byte[] privateKey, byte[] publicKey) {

    public static final int KEY_LENGTH = X25519.SCALAR_SIZE;

    public X25519KeyPair {
        if (privateKey.length != KEY_LENGTH || publicKey.length != KEY_LENGTH) {
            throw new IllegalArgumentException("X25519 keys are " + KEY_LENGTH + " bytes");
        }
        privateKey = privateKey.clone();
        publicKey = publicKey.clone();
    }

    public static X25519KeyPair fromPrivateKey(byte[] privateKey) {
        byte[] publicKey = new byte[KEY_LENGTH];
        X25519.scalarMultBase(privateKey, 0, publicKey, 0);
        return new X25519KeyPair(privateKey, publicKey);
    }

    public static X25519KeyPair generate(SecureRandom random) {
        byte[] privateKey = new byte[KEY_LENGTH];
        X25519.generatePrivateKey(random, privateKey);
        return fromPrivateKey(privateKey);
    }

    @Override
    public byte[] privateKey() {
        return privateKey.clone();
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof X25519KeyPair pair && Arrays.equals(publicKey, pair.publicKey) && Arrays.equals(privateKey, pair.privateKey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(publicKey);
    }

    @Override
    public String toString() {
        return "X25519KeyPair[public=" + Hex.encode(publicKey) + "]";
    }
}
