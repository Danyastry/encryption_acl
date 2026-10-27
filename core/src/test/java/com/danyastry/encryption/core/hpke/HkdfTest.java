package com.danyastry.encryption.core.hpke;

import static org.assertj.core.api.Assertions.assertThat;

import com.danyastry.encryption.core.util.Hex;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class HkdfTest {

    @Test
    void matchesRfc5869TestCase1() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);

        byte[] prk = Hkdf.extract(Hex.decode("000102030405060708090a0b0c"), ikm);
        byte[] okm = Hkdf.expand(prk, Hex.decode("f0f1f2f3f4f5f6f7f8f9"), 42);

        assertThat(Hex.encode(prk)).isEqualTo("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        assertThat(Hex.encode(okm)).isEqualTo("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    @Test
    void matchesRfc5869TestCase3WithoutSaltOrInfo() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);

        byte[] prk = Hkdf.extract(new byte[0], ikm);

        assertThat(Hex.encode(prk)).isEqualTo("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        assertThat(Hex.encode(Hkdf.expand(prk, new byte[0], 42)))
                .isEqualTo("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }
}
