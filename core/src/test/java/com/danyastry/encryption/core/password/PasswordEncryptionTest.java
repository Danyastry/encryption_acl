package com.danyastry.encryption.core.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.kdf.Argon2idParameters;
import com.danyastry.encryption.core.kdf.Pbkdf2Parameters;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class PasswordEncryptionTest {

    private static final PasswordEncryption FAST_ARGON = new PasswordEncryption(new Argon2idParameters(64, 1, 1));
    private static final PasswordEncryption FAST_PBKDF2 = new PasswordEncryption(new Pbkdf2Parameters(1_000));
    private static final byte[] MESSAGE = "Meet at noon".getBytes(StandardCharsets.UTF_8);

    @Test
    void roundTripsWithBothKdfs() throws Exception {
        for (PasswordEncryption encryption : new PasswordEncryption[] {FAST_ARGON, FAST_PBKDF2}) {
            byte[] envelope = encryption.encrypt(MESSAGE, "secret".toCharArray());

            assertThat(PasswordEncryption.decrypt(envelope, "secret".toCharArray())).isEqualTo(MESSAGE);
            assertThat(PasswordEnvelope.parse(envelope).kdf()).isEqualTo(encryption.kdf());
        }
    }

    @Test
    void startsWithTheMagicAndVersion() {
        byte[] envelope = FAST_ARGON.encrypt(MESSAGE, "secret".toCharArray());

        assertThat(new String(envelope, 0, 4, StandardCharsets.US_ASCII)).isEqualTo("EACL");
        assertThat(envelope[4]).isEqualTo((byte) 1);
        assertThat(envelope[6]).isEqualTo((byte) 0x02);
    }

    @Test
    void sameMessageAndPasswordNeverGiveTheSameBytes() {
        assertThat(FAST_ARGON.encrypt(MESSAGE, "secret".toCharArray())).isNotEqualTo(FAST_ARGON.encrypt(MESSAGE, "secret".toCharArray()));
    }

    @Test
    void wrongPasswordFailsAuthentication() {
        byte[] envelope = FAST_ARGON.encrypt(MESSAGE, "secret".toCharArray());

        assertFailure(envelope, "Secret", DecryptionFailure.AUTHENTICATION_FAILED);
    }

    @Test
    void everyChangedByteIsDetected() {
        byte[] envelope = FAST_PBKDF2.encrypt(MESSAGE, "secret".toCharArray());

        for (int i = 7; i < envelope.length; i++) {
            byte[] tampered = envelope.clone();
            tampered[i] ^= 0x01;
            assertThatThrownBy(() -> PasswordEncryption.decrypt(tampered, "secret".toCharArray()))
                    .as("byte %d", i)
                    .isInstanceOf(DecryptionException.class);
        }
    }

    @Test
    void downgradingTheKdfParametersIsDetected() {
        byte[] envelope = FAST_PBKDF2.encrypt(MESSAGE, "secret".toCharArray());
        ByteBuffer.wrap(envelope).putInt(7, 999);

        assertFailure(envelope, "secret", DecryptionFailure.AUTHENTICATION_FAILED);
    }

    @Test
    void refusesHeadersThatAskForTooMuchWork() {
        byte[] envelope = FAST_ARGON.encrypt(MESSAGE, "secret".toCharArray());
        ByteBuffer.wrap(envelope).putInt(7, Integer.MAX_VALUE);

        assertFailure(envelope, "secret", DecryptionFailure.MALFORMED);
    }

    @Test
    void explainsWhatIsWrongWithTheInput() {
        byte[] envelope = FAST_ARGON.encrypt(MESSAGE, "secret".toCharArray());

        assertFailure("not an envelope".getBytes(StandardCharsets.US_ASCII), "secret", DecryptionFailure.NOT_AN_ENVELOPE);
        assertFailure(java.util.Arrays.copyOf(envelope, 20), "secret", DecryptionFailure.MALFORMED);
        byte[] newer = envelope.clone();
        newer[4] = 2;
        assertFailure(newer, "secret", DecryptionFailure.UNSUPPORTED_VERSION);
        byte[] otherType = envelope.clone();
        otherType[5] = 0x02;
        assertFailure(otherType, "secret", DecryptionFailure.WRONG_TYPE);
        byte[] unknownKdf = envelope.clone();
        unknownKdf[6] = 0x7F;
        assertFailure(unknownKdf, "secret", DecryptionFailure.MALFORMED);
    }

    @Test
    void handlesEmptyMessagesAndUnicodePasswords() throws Exception {
        char[] password = "пароль 🔑".toCharArray();
        byte[] envelope = FAST_ARGON.encrypt(new byte[0], password);

        assertThat(PasswordEncryption.decrypt(envelope, "пароль 🔑".toCharArray())).isEmpty();
        assertThat(password).containsExactly("пароль 🔑".toCharArray());
    }

    @Test
    void defaultsMeetTheRecommendation() {
        assertThat(PasswordEncryption.recommended().kdf().meetsRecommendation()).isTrue();
    }

    private static void assertFailure(byte[] envelope, String password, DecryptionFailure expected) {
        assertThatThrownBy(() -> PasswordEncryption.decrypt(envelope, password.toCharArray()))
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(expected));
    }
}
