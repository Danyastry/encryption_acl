package com.danyastry.encryption.core.kdf;

public enum KdfAlgorithm {
    PBKDF2_HMAC_SHA256(0x01),
    ARGON2ID(0x02);

    private final int id;

    KdfAlgorithm(int id) {
        this.id = id;
    }

    public int id() {
        return id;
    }

    public static KdfAlgorithm of(int id) {
        for (KdfAlgorithm algorithm : values()) {
            if (algorithm.id == id) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown KDF id " + id);
    }
}
