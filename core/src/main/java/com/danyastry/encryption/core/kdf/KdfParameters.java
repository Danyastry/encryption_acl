package com.danyastry.encryption.core.kdf;

public sealed interface KdfParameters permits Pbkdf2Parameters, Argon2idParameters {

    KdfAlgorithm algorithm();

    byte[] derive(char[] password, byte[] salt, int length);

    boolean meetsRecommendation();
}
