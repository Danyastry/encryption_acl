package com.danyastry.encryption.core.signature;

import com.danyastry.encryption.core.util.Hex;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

public record Ed25519KeyPair(byte[] privateKey, byte[] publicKey) {

    public static final int KEY_LENGTH = Ed25519.SECRET_KEY_SIZE;

    public Ed25519KeyPair {
        if (privateKey.length != KEY_LENGTH || publicKey.length != Ed25519.PUBLIC_KEY_SIZE) {
            throw new IllegalArgumentException("Ed25519 keys are 32 bytes");
        }
        privateKey = privateKey.clone();
        publicKey = publicKey.clone();
    }

    public static Ed25519KeyPair fromPrivateKey(byte[] privateKey) {
        byte[] publicKey = new byte[Ed25519.PUBLIC_KEY_SIZE];
        Ed25519.generatePublicKey(privateKey, 0, publicKey, 0);
        return new Ed25519KeyPair(privateKey, publicKey);
    }

    public static Ed25519KeyPair generate(SecureRandom random) {
        byte[] privateKey = new byte[KEY_LENGTH];
        Ed25519.generatePrivateKey(random, privateKey);
        return fromPrivateKey(privateKey);
    }

    public byte[] sign(byte[] message) {
        byte[] signature = new byte[Ed25519.SIGNATURE_SIZE];
        Ed25519.sign(privateKey, 0, publicKey, 0, message, 0, message.length, signature, 0);
        return signature;
    }

    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey.length != Ed25519.PUBLIC_KEY_SIZE || signature.length != Ed25519.SIGNATURE_SIZE) {
            return false;
        }
        return Ed25519.verify(signature, 0, publicKey, 0, message, 0, message.length);
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
        return other instanceof Ed25519KeyPair pair && Arrays.equals(publicKey, pair.publicKey) && Arrays.equals(privateKey, pair.privateKey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(publicKey);
    }

    @Override
    public String toString() {
        return "Ed25519KeyPair[public=" + Hex.encode(publicKey) + "]";
    }
}
