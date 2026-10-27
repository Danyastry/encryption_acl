package com.danyastry.encryption.core.aead;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.util.Hex;
import java.nio.charset.StandardCharsets;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;

class ChaCha20Poly1305Test {

    private static final byte[] KEY = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static final byte[] NONCE = Hex.decode("070000004041424344454647");
    private static final byte[] AAD = Hex.decode("50515253c0c1c2c3c4c5c6c7");
    private static final byte[] PLAINTEXT = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future,"
            + " sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);

    @Test
    void matchesRfc8439Section282() {
        byte[] sealed = ChaCha20Poly1305.seal(KEY, NONCE, AAD, PLAINTEXT);

        assertThat(Hex.encode(sealed)).isEqualTo(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
                        + "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                        + "3ff4def08e4b7a9de576d26586cec64b6116"
                        + "1ae10b594f09e26a7e902ecbd0600691");
    }

    @Test
    void opensAndRejectsTampering() throws Exception {
        byte[] sealed = ChaCha20Poly1305.seal(KEY, NONCE, AAD, PLAINTEXT);

        assertThat(ChaCha20Poly1305.open(KEY, NONCE, AAD, sealed)).isEqualTo(PLAINTEXT);
        sealed[0] ^= 1;
        assertThatThrownBy(() -> ChaCha20Poly1305.open(KEY, NONCE, AAD, sealed)).isInstanceOf(AEADBadTagException.class);
    }
}
