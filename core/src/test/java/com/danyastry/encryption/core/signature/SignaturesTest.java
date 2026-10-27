package com.danyastry.encryption.core.signature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.util.Fingerprint;
import com.danyastry.encryption.core.util.Hex;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class SignaturesTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] CONTRACT = "I agree to pay 100 EUR".getBytes(StandardCharsets.UTF_8);

    private final Ed25519KeyPair alice = Ed25519KeyPair.generate(RANDOM);
    private final Ed25519KeyPair mallory = Ed25519KeyPair.generate(RANDOM);

    @Test
    void verifiesASignatureFromTheTrustedKey() throws Exception {
        byte[] signature = Signatures.sign(CONTRACT, alice);

        SignatureEnvelope envelope = Signatures.verify(CONTRACT, signature, alice.publicKey());

        assertThat(envelope.signerPublicKey()).isEqualTo(alice.publicKey());
        assertThat(signature).hasSize(SignatureEnvelope.LENGTH);
    }

    @Test
    void rejectsChangedData() {
        byte[] signature = Signatures.sign(CONTRACT, alice);
        byte[] changed = "I agree to pay 900 EUR".getBytes(StandardCharsets.UTF_8);

        assertFailure(() -> Signatures.verify(changed, signature, alice.publicKey()), VerificationFailure.INVALID_SIGNATURE);
    }

    @Test
    void rejectsAnotherSignerEvenWithAValidSignature() {
        byte[] signature = Signatures.sign(CONTRACT, mallory);

        assertFailure(() -> Signatures.verify(CONTRACT, signature, alice.publicKey()), VerificationFailure.WRONG_SIGNER);
    }

    @Test
    void rejectsASignerKeySwappedIntoTheEnvelope() {
        byte[] signature = Signatures.sign(CONTRACT, mallory);
        System.arraycopy(alice.publicKey(), 0, signature, 7, Ed25519KeyPair.KEY_LENGTH);

        assertFailure(() -> Signatures.verify(CONTRACT, signature, alice.publicKey()), VerificationFailure.INVALID_SIGNATURE);
    }

    @Test
    void rejectsEveryChangedSignatureByte() {
        byte[] signature = Signatures.sign(CONTRACT, alice);

        for (int i = SignatureEnvelope.HEADER_LENGTH; i < signature.length; i++) {
            byte[] tampered = signature.clone();
            tampered[i] ^= 0x01;
            assertFailure(() -> Signatures.verify(CONTRACT, tampered, alice.publicKey()), VerificationFailure.INVALID_SIGNATURE);
        }
    }

    @Test
    void aRawEd25519SignatureOverTheMessageAloneIsNotAccepted() {
        byte[] raw = alice.sign(CONTRACT);
        byte[] envelope = new SignatureEnvelope(alice.publicKey(), raw).encode();

        assertFailure(() -> Signatures.verify(CONTRACT, envelope, alice.publicKey()), VerificationFailure.INVALID_SIGNATURE);
    }

    @Test
    void explainsBrokenSignatures() {
        byte[] signature = Signatures.sign(CONTRACT, alice);
        byte[] newer = signature.clone();
        newer[4] = 2;
        byte[] otherAlgorithm = signature.clone();
        otherAlgorithm[6] = 0x09;

        assertFailure(() -> Signatures.verify(CONTRACT, "nope".getBytes(StandardCharsets.US_ASCII), alice.publicKey()), VerificationFailure.NOT_A_SIGNATURE);
        assertFailure(() -> Signatures.verify(CONTRACT, newer, alice.publicKey()), VerificationFailure.UNSUPPORTED_VERSION);
        assertFailure(() -> Signatures.verify(CONTRACT, otherAlgorithm, alice.publicKey()), VerificationFailure.MALFORMED);
        assertFailure(() -> Signatures.verify(CONTRACT, Arrays.copyOf(signature, 50), alice.publicKey()), VerificationFailure.MALFORMED);
    }

    @Test
    void fingerprintsAreShortAndStable() {
        String fingerprint = Fingerprint.of(Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));

        assertThat(fingerprint).matches("[0-9a-f]{4}(:[0-9a-f]{4}){3}");
        assertThat(Fingerprint.of(Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))).isEqualTo(fingerprint);
        assertThat(Fingerprint.of(alice.publicKey())).isNotEqualTo(Fingerprint.of(mallory.publicKey()));
    }

    private static void assertFailure(Executable action, VerificationFailure expected) {
        assertThatThrownBy(action::execute)
                .isInstanceOfSatisfying(VerificationException.class, e -> assertThat(e.failure()).isEqualTo(expected));
    }
}
