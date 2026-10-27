package com.danyastry.encryption.core.hpke;

public record Encapsulation(byte[] enc, byte[] sharedSecret) {

    public Encapsulation {
        enc = enc.clone();
        sharedSecret = sharedSecret.clone();
    }

    @Override
    public byte[] enc() {
        return enc.clone();
    }

    @Override
    public byte[] sharedSecret() {
        return sharedSecret.clone();
    }
}
