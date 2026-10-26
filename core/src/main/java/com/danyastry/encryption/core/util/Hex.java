package com.danyastry.encryption.core.util;

public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xFF;
            out[i * 2] = DIGITS[value >>> 4];
            out[i * 2 + 1] = DIGITS[value & 0x0F];
        }
        return new String(out);
    }

    public static byte[] decode(String text) {
        String clean = text.replaceAll("\\s", "");
        if (clean.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex needs an even number of digits, got " + clean.length());
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(clean.charAt(i * 2), 16);
            int low = Character.digit(clean.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Not a hex digit near position " + i * 2);
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
}
