package com.danyastry.encryption.core.acl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.stream.StreamChunks;
import com.danyastry.encryption.core.util.Fingerprint;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

class RecipientFilesTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int COUNT_OFFSET = 6;
    private static final int HEADER_FIXED = 7;

    private final RecipientFiles files = new RecipientFiles();
    private final X25519KeyPair alice = X25519KeyPair.generate(RANDOM);
    private final X25519KeyPair bob = X25519KeyPair.generate(RANDOM);
    private final X25519KeyPair carol = X25519KeyPair.generate(RANDOM);
    private final X25519KeyPair mallory = X25519KeyPair.generate(RANDOM);
    private final byte[] report = randomBytes(3 * StreamChunks.CHUNK_SIZE + 123, 1);

    @Test
    void everyRecipientCanOpenTheFile() throws Exception {
        byte[] encrypted = encrypt(report, alice, bob, carol);

        for (X25519KeyPair recipient : List.of(alice, bob, carol)) {
            assertThat(decrypt(encrypted, recipient)).isEqualTo(report);
        }
    }

    @Test
    void outsidersAreToldTheyAreNotRecipients() {
        byte[] encrypted = encrypt(report, alice, bob);

        assertFailure(encrypted, mallory, DecryptionFailure.NOT_A_RECIPIENT);
    }

    @Test
    void listsRecipientsByFingerprint() throws Exception {
        byte[] encrypted = encrypt(report, alice, bob, alice);

        assertThat(RecipientFiles.recipients(new ByteArrayInputStream(encrypted)))
                .containsExactly(Fingerprint.of(alice.publicKey()), Fingerprint.of(bob.publicKey()));
    }

    @Test
    void addingARecipientRewritesOnlyTheHeader() throws Exception {
        byte[] encrypted = encrypt(report, alice, bob);

        byte[] shared = change(encrypted, alice, List.of(carol.publicKey()), List.of());

        assertThat(decrypt(shared, carol)).isEqualTo(report);
        assertThat(decrypt(shared, bob)).isEqualTo(report);
        assertThat(payload(shared)).isEqualTo(payload(encrypted));
        assertThat(RecipientFiles.recipients(new ByteArrayInputStream(shared))).hasSize(3);
    }

    @Test
    void removingARecipientTakesThemOffTheFile() throws Exception {
        byte[] encrypted = encrypt(report, alice, bob, carol);

        byte[] reduced = change(encrypted, alice, List.of(), List.of(Fingerprint.of(bob.publicKey())));

        assertFailure(reduced, bob, DecryptionFailure.NOT_A_RECIPIENT);
        assertThat(decrypt(reduced, carol)).isEqualTo(report);
    }

    @Test
    void rekeyGivesAFreshFileKeySoOldStanzasAreUseless() throws Exception {
        byte[] encrypted = encrypt(report, alice, bob);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        files.rekey(new ByteArrayInputStream(encrypted), out, alice, List.of(alice.publicKey()));

        byte[] rekeyed = out.toByteArray();
        assertThat(decrypt(rekeyed, alice)).isEqualTo(report);
        assertFailure(rekeyed, bob, DecryptionFailure.NOT_A_RECIPIENT);
        assertThat(payload(rekeyed)).isNotEqualTo(payload(encrypted));
    }

    @Test
    void onlyARecipientCanChangeTheList() {
        byte[] encrypted = encrypt(report, alice, bob);

        assertThatThrownBy(() -> change(encrypted, mallory, List.of(mallory.publicKey()), List.of()))
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(DecryptionFailure.NOT_A_RECIPIENT));
    }

    @Test
    void refusesToRemoveEveryoneOrSomeoneWhoIsNotListed() {
        byte[] encrypted = encrypt(report, alice);

        assertThatThrownBy(() -> change(encrypted, alice, List.of(), List.of(Fingerprint.of(alice.publicKey()))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> change(encrypted, alice, List.of(), List.of(Fingerprint.of(mallory.publicKey()))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aSpliceOfStanzasIsCaughtByTheHeaderMac() throws Exception {
        byte[] forAlice = encrypt(report, alice);
        byte[] forBob = encrypt(randomBytes(500, 2), bob);
        int stanzaStart = HEADER_FIXED;
        byte[] spliced = forAlice.clone();
        spliced[COUNT_OFFSET] = 2;
        byte[] withExtra = new byte[spliced.length + RecipientStanza.LENGTH];
        System.arraycopy(spliced, 0, withExtra, 0, stanzaStart + RecipientStanza.LENGTH);
        System.arraycopy(forBob, stanzaStart, withExtra, stanzaStart + RecipientStanza.LENGTH, RecipientStanza.LENGTH);
        System.arraycopy(spliced, stanzaStart + RecipientStanza.LENGTH, withExtra, stanzaStart + 2 * RecipientStanza.LENGTH,
                spliced.length - stanzaStart - RecipientStanza.LENGTH);

        assertFailure(withExtra, alice, DecryptionFailure.AUTHENTICATION_FAILED);
        assertFailure(withExtra, bob, DecryptionFailure.AUTHENTICATION_FAILED);
    }

    @Test
    void everyChangedHeaderByteIsDetected() {
        byte[] encrypted = encrypt(randomBytes(100, 3), alice);
        int headerLength = HEADER_FIXED + RecipientStanza.LENGTH + StreamChunks.PAYLOAD_NONCE_LENGTH + RecipientHeader.MAC_LENGTH;

        for (int i = COUNT_OFFSET; i < headerLength; i++) {
            byte[] tampered = encrypted.clone();
            tampered[i] ^= 0x01;
            assertThatThrownBy(() -> decrypt(tampered, alice)).as("byte %d", i).isInstanceOf(DecryptionException.class);
        }
    }

    @Test
    void detectsTruncationLikeAnyStream() {
        byte[] encrypted = encrypt(report, alice);
        int header = encrypted.length - payload(encrypted).length;
        byte[] cut = Arrays.copyOf(encrypted, header + 2 * StreamChunks.SEALED_CHUNK_SIZE);

        assertFailure(cut, alice, DecryptionFailure.TRUNCATED);
    }

    @Test
    void damagedContentIsNeverBlamedOnTheKey() {
        byte[] encrypted = encrypt(report, alice);
        int header = encrypted.length - payload(encrypted).length;
        byte[] damaged = encrypted.clone();
        damaged[header + 5] ^= 1;

        assertFailure(damaged, alice, DecryptionFailure.DAMAGED);
        assertFailure(Arrays.copyOf(encrypted, encrypted.length - 1000), alice, DecryptionFailure.DAMAGED);
    }

    @Test
    void needsAtLeastOneValidRecipient() {
        assertThatThrownBy(() -> files.encrypt(new ByteArrayInputStream(report), new ByteArrayOutputStream(), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> files.encrypt(new ByteArrayInputStream(report), new ByteArrayOutputStream(), List.of(new byte[5])))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private byte[] encrypt(byte[] plaintext, X25519KeyPair... recipients) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            files.encrypt(new ByteArrayInputStream(plaintext), out, Arrays.stream(recipients).map(X25519KeyPair::publicKey).toList());
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] change(byte[] encrypted, X25519KeyPair me, List<byte[]> add, List<String> remove) throws IOException, DecryptionException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        files.changeRecipients(new ByteArrayInputStream(encrypted), out, me, add, remove);
        return out.toByteArray();
    }

    private static byte[] decrypt(byte[] encrypted, X25519KeyPair me) throws IOException, DecryptionException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        RecipientFiles.decrypt(new ByteArrayInputStream(encrypted), out, me);
        return out.toByteArray();
    }

    private static byte[] payload(byte[] encrypted) {
        int count = encrypted[COUNT_OFFSET] & 0xFF;
        int header = HEADER_FIXED + count * RecipientStanza.LENGTH + StreamChunks.PAYLOAD_NONCE_LENGTH + RecipientHeader.MAC_LENGTH;
        return Arrays.copyOfRange(encrypted, header, encrypted.length);
    }

    private static void assertFailure(byte[] encrypted, X25519KeyPair me, DecryptionFailure expected) {
        assertThatThrownBy(() -> decrypt(encrypted, me))
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(expected));
    }

    private static byte[] randomBytes(int size, long seed) {
        byte[] bytes = new byte[size];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }
}
