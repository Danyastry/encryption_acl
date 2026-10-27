package com.danyastry.encryption.core.legacy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class LegacyStandardFormatTest {

    private static final String MADE_BY_OLD_APP =
            "d0MfG72I0LwCWbrKCRM8GsW4+tKkqjndTFC/DyQc3txJaTSVApPNwlLnn+kiJq26CF7FneDrwn6LgJx6UfbADT1/";

    @Test
    void opensMessagesFromTheOriginalStandardEncryption() throws Exception {
        byte[] plaintext = LegacyStandardFormat.decrypt(MADE_BY_OLD_APP, "correct horse".toCharArray());

        assertThat(new String(plaintext, StandardCharsets.UTF_8)).isEqualTo("Hello from the old app");
    }

    @Test
    void rejectsAWrongPasswordAndBrokenInput() {
        assertThatThrownBy(() -> LegacyStandardFormat.decrypt(MADE_BY_OLD_APP, "wrong".toCharArray()))
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(DecryptionFailure.AUTHENTICATION_FAILED));
        assertThatThrownBy(() -> LegacyStandardFormat.decrypt("!!!", "x".toCharArray()))
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(DecryptionFailure.MALFORMED));
        assertThatThrownBy(() -> LegacyStandardFormat.decrypt("AAAA", "x".toCharArray()))
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(DecryptionFailure.MALFORMED));
    }
}
