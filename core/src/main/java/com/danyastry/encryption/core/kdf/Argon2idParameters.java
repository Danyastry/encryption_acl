package com.danyastry.encryption.core.kdf;

public record Argon2idParameters(int memoryKiB, int iterations, int parallelism) implements KdfParameters {

    public static final int MAX_MEMORY_KIB = 1 << 20;
    public static final int MAX_ITERATIONS = 10;
    public static final int MAX_PARALLELISM = 16;

    public Argon2idParameters {
        if (parallelism < 1 || parallelism > MAX_PARALLELISM) {
            throw new IllegalArgumentException("Argon2 parallelism must be 1.." + MAX_PARALLELISM + ", got " + parallelism);
        }
        if (iterations < 1 || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("Argon2 iterations must be 1.." + MAX_ITERATIONS + ", got " + iterations);
        }
        if (memoryKiB < 8 * parallelism || memoryKiB > MAX_MEMORY_KIB) {
            throw new IllegalArgumentException("Argon2 memory must be " + 8 * parallelism + ".." + MAX_MEMORY_KIB + " KiB, got " + memoryKiB);
        }
    }

    public static Argon2idParameters recommended() {
        return new Argon2idParameters(64 * 1024, 3, 4);
    }

    @Override
    public KdfAlgorithm algorithm() {
        return KdfAlgorithm.ARGON2ID;
    }

    @Override
    public byte[] derive(char[] password, byte[] salt, int length) {
        return Argon2id.derive(password, salt, this, length);
    }

    @Override
    public boolean meetsRecommendation() {
        return memoryKiB >= 19 * 1024 && iterations >= 2;
    }
}
