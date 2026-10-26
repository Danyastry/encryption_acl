package com.danyastry.encryption.core.aead;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.util.Hex;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;

class AesGcmTest {

    private static final byte[] KEY = Hex.decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    private static final byte[] NONCE = Hex.decode("cafebabefacedbaddecaf888");
    private static final byte[] PLAINTEXT = Hex.decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                    + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

    @Test
    void matchesGcmSpecTestCase15() {
        byte[] sealed = AesGcm.encrypt(KEY, NONCE, new byte[0], PLAINTEXT);

        assertThat(Hex.encode(sealed)).isEqualTo(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                        + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
                        + "b094dac5d93471bdec1a502270e3cc6c");
    }

    @Test
    void rejectsChangedCiphertextOrAad() throws Exception {
        byte[] sealed = AesGcm.encrypt(KEY, NONCE, "header".getBytes(), PLAINTEXT);

        assertThat(AesGcm.decrypt(KEY, NONCE, "header".getBytes(), sealed)).isEqualTo(PLAINTEXT);
        sealed[3] ^= 1;
        assertThatThrownBy(() -> AesGcm.decrypt(KEY, NONCE, "header".getBytes(), sealed)).isInstanceOf(AEADBadTagException.class);
        sealed[3] ^= 1;
        assertThatThrownBy(() -> AesGcm.decrypt(KEY, NONCE, "Header".getBytes(), sealed)).isInstanceOf(AEADBadTagException.class);
    }

    @Test
    void checksKeyAndNonceLengths() {
        assertThatThrownBy(() -> AesGcm.encrypt(new byte[16], NONCE, new byte[0], PLAINTEXT)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AesGcm.encrypt(KEY, new byte[16], new byte[0], PLAINTEXT)).isInstanceOf(IllegalArgumentException.class);
    }
}
