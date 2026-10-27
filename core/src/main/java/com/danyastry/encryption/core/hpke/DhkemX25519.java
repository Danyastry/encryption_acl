package com.danyastry.encryption.core.hpke;

import java.security.SecureRandom;
import org.bouncycastle.math.ec.rfc7748.X25519;

public final class DhkemX25519 {

    public static final int KEM_ID = 0x0020;
    public static final int SECRET_LENGTH = 32;

    private static final LabeledKdf KDF = new LabeledKdf(LabeledKdf.concat(LabeledKdf.ascii("KEM"), new byte[] {0x00, 0x20}));

    private DhkemX25519() {
    }

    public static X25519KeyPair deriveKeyPair(byte[] ikm) {
        byte[] prk = KDF.extract(new byte[0], "dkp_prk", ikm);
        return X25519KeyPair.fromPrivateKey(KDF.expand(prk, "sk", new byte[0], X25519KeyPair.KEY_LENGTH));
    }

    public static Encapsulation encap(byte[] recipientPublicKey, SecureRandom random) {
        return encap(recipientPublicKey, X25519KeyPair.generate(random));
    }

    static Encapsulation encap(byte[] recipientPublicKey, X25519KeyPair ephemeral) {
        byte[] dh = dh(ephemeral.privateKey(), recipientPublicKey);
        byte[] enc = ephemeral.publicKey();
        return new Encapsulation(enc, extractAndExpand(dh, LabeledKdf.concat(enc, recipientPublicKey)));
    }

    public static byte[] decap(byte[] enc, X25519KeyPair recipient) {
        byte[] dh = dh(recipient.privateKey(), enc);
        return extractAndExpand(dh, LabeledKdf.concat(enc, recipient.publicKey()));
    }

    public static Encapsulation authEncap(byte[] recipientPublicKey, X25519KeyPair sender, SecureRandom random) {
        return authEncap(recipientPublicKey, sender, X25519KeyPair.generate(random));
    }

    static Encapsulation authEncap(byte[] recipientPublicKey, X25519KeyPair sender, X25519KeyPair ephemeral) {
        byte[] dh = LabeledKdf.concat(dh(ephemeral.privateKey(), recipientPublicKey), dh(sender.privateKey(), recipientPublicKey));
        byte[] enc = ephemeral.publicKey();
        return new Encapsulation(enc, extractAndExpand(dh, LabeledKdf.concat(enc, recipientPublicKey, sender.publicKey())));
    }

    public static byte[] authDecap(byte[] enc, X25519KeyPair recipient, byte[] senderPublicKey) {
        byte[] dh = LabeledKdf.concat(dh(recipient.privateKey(), enc), dh(recipient.privateKey(), senderPublicKey));
        return extractAndExpand(dh, LabeledKdf.concat(enc, recipient.publicKey(), senderPublicKey));
    }

    private static byte[] dh(byte[] privateKey, byte[] publicKey) {
        if (publicKey.length != X25519KeyPair.KEY_LENGTH) {
            throw new IllegalArgumentException("X25519 public keys are 32 bytes");
        }
        byte[] shared = new byte[X25519.POINT_SIZE];
        if (!X25519.calculateAgreement(privateKey, 0, publicKey, 0, shared, 0)) {
            throw new IllegalArgumentException("X25519 produced the all-zero shared secret");
        }
        return shared;
    }

    private static byte[] extractAndExpand(byte[] dh, byte[] kemContext) {
        byte[] prk = KDF.extract(new byte[0], "eae_prk", dh);
        return KDF.expand(prk, "shared_secret", kemContext, SECRET_LENGTH);
    }
}
