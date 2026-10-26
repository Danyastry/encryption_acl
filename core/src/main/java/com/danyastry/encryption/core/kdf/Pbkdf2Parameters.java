package com.danyastry.encryption.core.kdf;

public record Pbkdf2Parameters(int iterations) implements KdfParameters {

    public static final int RECOMMENDED_ITERATIONS = 600_000;
    public static final int MAX_ITERATIONS = 10_000_000;

    public Pbkdf2Parameters {
        if (iterations < 1 || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("PBKDF2 iterations must be 1.." + MAX_ITERATIONS + ", got " + iterations);
        }
    }

    public static Pbkdf2Parameters recommended() {
        return new Pbkdf2Parameters(RECOMMENDED_ITERATIONS);
    }

    @Override
    public KdfAlgorithm algorithm() {
        return KdfAlgorithm.PBKDF2_HMAC_SHA256;
    }

    @Override
    public byte[] derive(char[] password, byte[] salt, int length) {
        return Pbkdf2.deriveSha256(password, salt, iterations, length);
    }

    @Override
    public boolean meetsRecommendation() {
        return iterations >= RECOMMENDED_ITERATIONS;
    }
}
