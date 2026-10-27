package com.danyastry.encryption.core.publickey;

import com.danyastry.encryption.core.aead.ChaCha20Poly1305;
import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.hpke.DhkemX25519;
import com.danyastry.encryption.core.hpke.Encapsulation;
import com.danyastry.encryption.core.hpke.Hpke;
import com.danyastry.encryption.core.hpke.HpkeMode;
import com.danyastry.encryption.core.hpke.X25519KeyPair;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;

public final class PublicKeyEncryption {

    static final byte[] INFO = "encryption_acl v1 message".getBytes(StandardCharsets.US_ASCII);

    private final SecureRandom random;

    public PublicKeyEncryption(SecureRandom random) {
        this.random = random;
    }

    public PublicKeyEncryption() {
        this(new SecureRandom());
    }

    public byte[] encrypt(byte[] plaintext, byte[] recipientPublicKey) {
        return seal(HpkeMode.BASE, DhkemX25519.encap(recipientPublicKey, random), plaintext);
    }

    public byte[] encryptFrom(byte[] plaintext, byte[] recipientPublicKey, X25519KeyPair sender) {
        return seal(HpkeMode.AUTH, DhkemX25519.authEncap(recipientPublicKey, sender, random), plaintext);
    }

    public static byte[] decrypt(byte[] envelopeBytes, X25519KeyPair recipient) throws DecryptionException {
        PublicKeyEnvelope envelope = PublicKeyEnvelope.parse(envelopeBytes);
        if (envelope.mode() == HpkeMode.AUTH) {
            throw new DecryptionException(DecryptionFailure.MISSING_SENDER_KEY);
        }
        return open(envelope, DhkemX25519.decap(envelope.enc(), recipient));
    }

    public static byte[] decryptFrom(byte[] envelopeBytes, X25519KeyPair recipient, byte[] senderPublicKey) throws DecryptionException {
        PublicKeyEnvelope envelope = PublicKeyEnvelope.parse(envelopeBytes);
        if (envelope.mode() != HpkeMode.AUTH) {
            throw new DecryptionException(DecryptionFailure.AUTHENTICATION_FAILED);
        }
        return open(envelope, DhkemX25519.authDecap(envelope.enc(), recipient, senderPublicKey));
    }

    private static byte[] seal(HpkeMode mode, Encapsulation encapsulation, byte[] plaintext) {
        byte[] header = new PublicKeyEnvelope(mode, encapsulation.enc(), new byte[ChaCha20Poly1305.TAG_LENGTH]).header();
        byte[] ciphertext = Hpke.keySchedule(mode, encapsulation.sharedSecret(), INFO).seal(header, plaintext);
        return new PublicKeyEnvelope(mode, encapsulation.enc(), ciphertext).encode();
    }

    private static byte[] open(PublicKeyEnvelope envelope, byte[] sharedSecret) throws DecryptionException {
        try {
            return Hpke.keySchedule(envelope.mode(), sharedSecret, INFO).open(envelope.header(), envelope.ciphertext());
        } catch (AEADBadTagException e) {
            throw new DecryptionException(DecryptionFailure.AUTHENTICATION_FAILED);
        }
    }
}
