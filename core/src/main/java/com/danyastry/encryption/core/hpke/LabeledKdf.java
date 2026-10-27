package com.danyastry.encryption.core.hpke;

import java.nio.charset.StandardCharsets;

final class LabeledKdf {

    private static final byte[] VERSION = "HPKE-v1".getBytes(StandardCharsets.US_ASCII);

    private final byte[] suiteId;

    LabeledKdf(byte[] suiteId) {
        this.suiteId = suiteId.clone();
    }

    byte[] extract(byte[] salt, String label, byte[] ikm) {
        return Hkdf.extract(salt, concat(VERSION, suiteId, ascii(label), ikm));
    }

    byte[] expand(byte[] prk, String label, byte[] info, int length) {
        byte[] lengthBytes = {(byte) (length >>> 8), (byte) length};
        return Hkdf.expand(prk, concat(lengthBytes, VERSION, suiteId, ascii(label), info), length);
    }

    static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }
}
