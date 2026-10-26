package com.danyastry.encryption.core.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class HexTest {

    @Test
    void encodesLowerCaseAndDecodesIgnoringSpaces() {
        assertThat(Hex.encode(new byte[] {0x00, 0x7F, (byte) 0x80, (byte) 0xFF})).isEqualTo("007f80ff");
        assertThat(Hex.decode("DE AD\nbe ef")).containsExactly(0xDE, 0xAD, 0xBE, 0xEF);
    }

    @Test
    void rejectsOddLengthAndNonHexDigits() {
        assertThatThrownBy(() -> Hex.decode("abc")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Hex.decode("zz")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void wipesSecrets() {
        byte[] key = {1, 2, 3};
        char[] password = {'p', 'w'};

        Secrets.wipe(key);
        Secrets.wipe(password);
        Secrets.wipe((byte[]) null);

        assertThat(key).containsOnly(0);
        assertThat(password).containsOnly('\0');
    }
}
