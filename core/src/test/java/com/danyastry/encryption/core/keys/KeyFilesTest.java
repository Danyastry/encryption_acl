package com.danyastry.encryption.core.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.kdf.Argon2idParameters;
import com.danyastry.encryption.core.password.PasswordEncryption;
import com.danyastry.encryption.core.util.Hex;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class KeyFilesTest {

    private static final PasswordEncryption FAST = new PasswordEncryption(new Argon2idParameters(64, 1, 1));

    private final Identity identity = Identity.generate(new SecureRandom());

    @Test
    void publicKeysRoundTripWithAFingerprintComment() throws Exception {
        String text = KeyFiles.encodePublic(identity.publicIdentity());

        assertThat(text).contains("-----BEGIN EACL PUBLIC KEY-----").contains("# fingerprint " + identity.fingerprint());
        assertThat(KeyFiles.parsePublic(text)).isEqualTo(identity.publicIdentity());
    }

    @Test
    void privateKeysAreEncryptedWithThePassphrase() throws Exception {
        String text = KeyFiles.encodePrivate(identity, FAST, "long passphrase".toCharArray());

        assertThat(KeyFiles.isProtected(text)).isTrue();
        assertThat(text).doesNotContain(Base64.getEncoder().encodeToString(identity.encryption().privateKey()));
        Identity restored = KeyFiles.parsePrivate(text, "long passphrase".toCharArray());
        assertThat(restored.publicIdentity()).isEqualTo(identity.publicIdentity());
        assertThat(Hex.encode(restored.signing().privateKey())).isEqualTo(Hex.encode(identity.signing().privateKey()));
    }

    @Test
    void aWrongPassphraseIsReported() {
        String text = KeyFiles.encodePrivate(identity, FAST, "right".toCharArray());

        assertThatThrownBy(() -> KeyFiles.parsePrivate(text, "wrong".toCharArray()))
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(DecryptionFailure.AUTHENTICATION_FAILED));
    }

    @Test
    void unprotectedKeysWorkWithoutAPassphrase() throws Exception {
        String text = KeyFiles.encodeUnprotectedPrivate(identity);

        assertThat(KeyFiles.isProtected(text)).isFalse();
        assertThat(KeyFiles.parsePrivate(text, null).fingerprint()).isEqualTo(identity.fingerprint());
    }

    @Test
    void refusesTheWrongKindOfFile() {
        String publicText = KeyFiles.encodePublic(identity.publicIdentity());

        assertThatThrownBy(() -> KeyFiles.parsePrivate(publicText, null)).isInstanceOf(KeyFileException.class).hasMessageContaining("found a eacl public key");
        assertThatThrownBy(() -> KeyFiles.parsePublic("hello")).isInstanceOf(KeyFileException.class);
        assertThatThrownBy(() -> KeyFiles.parsePublic("-----BEGIN EACL PUBLIC KEY-----\nAAAA\n-----END EACL PUBLIC KEY-----"))
                .isInstanceOf(KeyFileException.class);
    }
}
