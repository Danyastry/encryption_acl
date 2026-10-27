package com.danyastry.encryption.core.publickey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.kdf.Pbkdf2Parameters;
import com.danyastry.encryption.core.password.PasswordEncryption;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class PublicKeyEncryptionTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] MESSAGE = "The report is ready".getBytes(StandardCharsets.UTF_8);

    private final PublicKeyEncryption encryption = new PublicKeyEncryption();
    private final X25519KeyPair alice = X25519KeyPair.generate(RANDOM);
    private final X25519KeyPair bob = X25519KeyPair.generate(RANDOM);
    private final X25519KeyPair mallory = X25519KeyPair.generate(RANDOM);

    @Test
    void anonymousMessagesOpenWithTheRecipientKeyOnly() throws Exception {
        byte[] envelope = encryption.encrypt(MESSAGE, bob.publicKey());

        assertThat(PublicKeyEncryption.decrypt(envelope, bob)).isEqualTo(MESSAGE);
        assertFailure(() -> PublicKeyEncryption.decrypt(envelope, mallory), DecryptionFailure.AUTHENTICATION_FAILED);
    }

    @Test
    void authenticatedMessagesProveTheSender() throws Exception {
        byte[] envelope = encryption.encryptFrom(MESSAGE, bob.publicKey(), alice);

        assertThat(PublicKeyEncryption.decryptFrom(envelope, bob, alice.publicKey())).isEqualTo(MESSAGE);
        assertFailure(() -> PublicKeyEncryption.decryptFrom(envelope, bob, mallory.publicKey()), DecryptionFailure.AUTHENTICATION_FAILED);
        assertFailure(() -> PublicKeyEncryption.decrypt(envelope, bob), DecryptionFailure.MISSING_SENDER_KEY);
    }

    @Test
    void anAnonymousMessageIsNotAcceptedAsAuthenticated() {
        byte[] envelope = encryption.encrypt(MESSAGE, bob.publicKey());

        assertFailure(() -> PublicKeyEncryption.decryptFrom(envelope, bob, alice.publicKey()), DecryptionFailure.AUTHENTICATION_FAILED);
    }

    @Test
    void everyMessageUsesAFreshEphemeralKey() throws Exception {
        PublicKeyEnvelope first = PublicKeyEnvelope.parse(encryption.encrypt(MESSAGE, bob.publicKey()));
        PublicKeyEnvelope second = PublicKeyEnvelope.parse(encryption.encrypt(MESSAGE, bob.publicKey()));

        assertThat(first.enc()).isNotEqualTo(second.enc());
        assertThat(first.ciphertext()).isNotEqualTo(second.ciphertext());
    }

    @Test
    void everyChangedByteIsDetected() {
        byte[] envelope = encryption.encryptFrom(MESSAGE, bob.publicKey(), alice);

        for (int i = 0; i < envelope.length; i++) {
            byte[] tampered = envelope.clone();
            tampered[i] ^= 0x01;
            assertThatThrownBy(() -> PublicKeyEncryption.decryptFrom(tampered, bob, alice.publicKey()))
                    .as("byte %d", i)
                    .isInstanceOf(DecryptionException.class);
        }
    }

    @Test
    void passwordAndPublicKeyEnvelopesAreNotMixedUp() {
        byte[] passwordEnvelope = new PasswordEncryption(new Pbkdf2Parameters(1_000)).encrypt(MESSAGE, "pw".toCharArray());
        byte[] publicKeyEnvelope = encryption.encrypt(MESSAGE, bob.publicKey());

        assertFailure(() -> PublicKeyEncryption.decrypt(passwordEnvelope, bob), DecryptionFailure.WRONG_TYPE);
        assertFailure(() -> PasswordEncryption.decrypt(publicKeyEnvelope, "pw".toCharArray()), DecryptionFailure.WRONG_TYPE);
    }

    @Test
    void rejectsTruncatedAndForeignData() {
        byte[] envelope = encryption.encrypt(MESSAGE, bob.publicKey());

        assertFailure(() -> PublicKeyEncryption.decrypt(java.util.Arrays.copyOf(envelope, 30), bob), DecryptionFailure.MALFORMED);
        assertFailure(() -> PublicKeyEncryption.decrypt("EAC".getBytes(StandardCharsets.US_ASCII), bob), DecryptionFailure.MALFORMED);
        assertFailure(() -> PublicKeyEncryption.decrypt("helloworld".getBytes(StandardCharsets.US_ASCII), bob), DecryptionFailure.NOT_AN_ENVELOPE);
    }

    @Test
    void neverPrintsPrivateKeys() {
        assertThat(alice.toString()).doesNotContain(com.danyastry.encryption.core.util.Hex.encode(alice.privateKey()));
    }

    private static void assertFailure(Executable action, DecryptionFailure expected) {
        assertThatThrownBy(action::execute)
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(expected));
    }
}
