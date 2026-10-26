package com.danyastry.encryption.core.kdf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.util.Hex;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Pbkdf2Test {

    @Test
    void matchesRfc7914SingleIteration() {
        byte[] key = Pbkdf2.deriveSha256("passwd".toCharArray(), "salt".getBytes(StandardCharsets.US_ASCII), 1, 64);

        assertThat(Hex.encode(key)).isEqualTo(
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                        + "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
    }

    @Test
    void matchesRfc7914EightyThousandIterations() {
        byte[] key = Pbkdf2.deriveSha256("Password".toCharArray(), "NaCl".getBytes(StandardCharsets.US_ASCII), 80_000, 64);

        assertThat(Hex.encode(key)).isEqualTo(
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                        + "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d");
    }

    @Test
    void parametersHaveBoundsAndARecommendation() {
        assertThat(Pbkdf2Parameters.recommended().iterations()).isEqualTo(600_000);
        assertThat(new Pbkdf2Parameters(65_536).meetsRecommendation()).isFalse();
        assertThatThrownBy(() -> new Pbkdf2Parameters(0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Pbkdf2Parameters(Pbkdf2Parameters.MAX_ITERATIONS + 1)).isInstanceOf(IllegalArgumentException.class);
    }
}
