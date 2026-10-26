package com.danyastry.encryption.core.kdf;

import com.danyastry.encryption.core.util.Passwords;
import com.danyastry.encryption.core.util.Secrets;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public final class Argon2id {

    private Argon2id() {
    }

    public static byte[] derive(char[] password, byte[] salt, Argon2idParameters parameters, int length) {
        byte[] passwordBytes = Passwords.utf8(password);
        try {
            return derive(passwordBytes, salt, null, null, parameters, length);
        } finally {
            Secrets.wipe(passwordBytes);
        }
    }

    static byte[] derive(byte[] password, byte[] salt, byte[] secret, byte[] associatedData, Argon2idParameters parameters, int length) {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(parameters.memoryKiB())
                .withIterations(parameters.iterations())
                .withParallelism(parameters.parallelism());
        if (secret != null) {
            builder.withSecret(secret);
        }
        if (associatedData != null) {
            builder.withAdditional(associatedData);
        }
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());
        byte[] out = new byte[length];
        generator.generateBytes(password, out);
        return out;
    }
}
