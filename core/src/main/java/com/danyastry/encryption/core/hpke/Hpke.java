package com.danyastry.encryption.core.hpke;

import com.danyastry.encryption.core.aead.ChaCha20Poly1305;

public final class Hpke {

    public static final int KDF_ID = 0x0001;
    public static final int AEAD_ID = 0x0003;
    public static final byte[] SUITE = {0x00, 0x20, 0x00, 0x01, 0x00, 0x03};

    private static final LabeledKdf KDF = new LabeledKdf(LabeledKdf.concat(LabeledKdf.ascii("HPKE"), SUITE));

    private Hpke() {
    }

    public static HpkeContext keySchedule(HpkeMode mode, byte[] sharedSecret, byte[] info) {
        byte[] pskIdHash = KDF.extract(new byte[0], "psk_id_hash", new byte[0]);
        byte[] infoHash = KDF.extract(new byte[0], "info_hash", info);
        byte[] context = LabeledKdf.concat(new byte[] {(byte) mode.id()}, pskIdHash, infoHash);
        byte[] secret = KDF.extract(sharedSecret, "secret", new byte[0]);
        return new HpkeContext(
                KDF.expand(secret, "key", context, ChaCha20Poly1305.KEY_LENGTH),
                KDF.expand(secret, "base_nonce", context, ChaCha20Poly1305.NONCE_LENGTH),
                KDF.expand(secret, "exp", context, Hkdf.HASH_LENGTH),
                KDF);
    }

    static byte[] keyScheduleContext(HpkeMode mode, byte[] info) {
        return LabeledKdf.concat(
                new byte[] {(byte) mode.id()},
                KDF.extract(new byte[0], "psk_id_hash", new byte[0]),
                KDF.extract(new byte[0], "info_hash", info));
    }
}
