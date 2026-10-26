package com.danyastry.encryption.core.kdf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.util.Hex;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class Argon2idTest {

    @Test
    void matchesRfc9106TestVector() {
        byte[] password = filled(32, 0x01);
        byte[] salt = filled(16, 0x02);
        byte[] secret = filled(8, 0x03);
        byte[] associatedData = filled(12, 0x04);

        byte[] tag = Argon2id.derive(password, salt, secret, associatedData, new Argon2idParameters(32, 3, 4), 32);

        assertThat(Hex.encode(tag)).isEqualTo("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }

    @Test
    void differentPasswordsAndSaltsGiveDifferentKeys() {
        Argon2idParameters cheap = new Argon2idParameters(64, 1, 1);
        byte[] salt = filled(16, 0x05);

        byte[] first = cheap.derive("one".toCharArray(), salt, 32);
        byte[] second = cheap.derive("two".toCharArray(), salt, 32);
        byte[] otherSalt = cheap.derive("one".toCharArray(), filled(16, 0x06), 32);

        assertThat(first).isNotEqualTo(second).isNotEqualTo(otherSalt);
        assertThat(cheap.derive("one".toCharArray(), salt, 32)).isEqualTo(first);
    }

    @Test
    void parametersHaveBoundsAndARecommendation() {
        assertThat(Argon2idParameters.recommended()).isEqualTo(new Argon2idParameters(65_536, 3, 4));
        assertThat(Argon2idParameters.recommended().meetsRecommendation()).isTrue();
        assertThat(new Argon2idParameters(64, 1, 1).meetsRecommendation()).isFalse();
        assertThatThrownBy(() -> new Argon2idParameters(Argon2idParameters.MAX_MEMORY_KIB + 1, 3, 4)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Argon2idParameters(16, 3, 4)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Argon2idParameters(64, 0, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Argon2idParameters(64, 1, 17)).isInstanceOf(IllegalArgumentException.class);
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
