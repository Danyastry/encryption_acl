package com.danyastry.encryption.core.stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.kdf.Argon2idParameters;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PasswordFileEncryptionTest {

    private static final int CHUNK = StreamChunks.CHUNK_SIZE;
    private static final char[] PASSWORD = "file password".toCharArray();
    private final PasswordFileEncryption encryption = new PasswordFileEncryption(new Argon2idParameters(64, 1, 1));

    @ParameterizedTest(name = "{0} bytes")
    @ValueSource(ints = {0, 1, 1000, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 17})
    void roundTripsAnySize(int size) throws Exception {
        byte[] plaintext = randomBytes(size, size);

        byte[] encrypted = encrypt(plaintext);

        assertThat(decrypt(encrypted)).isEqualTo(plaintext);
        int chunks = size == 0 ? 1 : (size + CHUNK - 1) / CHUNK;
        assertThat(encrypted.length - headerLength(encrypted)).isEqualTo(size + chunks * 16);
    }

    @Test
    void streamsWithoutHoldingTheWholeFile() throws Exception {
        long size = 20L * CHUNK + 5;
        CountingSink sink = new CountingSink();

        long written = encryption.encrypt(new PatternStream(size), sink, PASSWORD);

        assertThat(written).isEqualTo(size);
        assertThat(sink.count).isEqualTo(headerLengthFor() + size + 21L * 16);
    }

    @Test
    void wrongPasswordFails() {
        byte[] encrypted = encrypt(randomBytes(500, 1));

        assertFailure(encrypted, "other password".toCharArray(), DecryptionFailure.AUTHENTICATION_FAILED);
    }

    @Test
    void detectsAFileCutAtAChunkBoundary() {
        byte[] encrypted = encrypt(randomBytes(3 * CHUNK + 10, 2));
        int header = headerLength(encrypted);
        byte[] cut = Arrays.copyOf(encrypted, header + 2 * StreamChunks.SEALED_CHUNK_SIZE);

        assertFailure(cut, PASSWORD, DecryptionFailure.TRUNCATED);
    }

    @Test
    void detectsAFileCutInsideAChunk() {
        byte[] encrypted = encrypt(randomBytes(2 * CHUNK, 3));

        assertFailure(Arrays.copyOf(encrypted, encrypted.length - 100), PASSWORD, DecryptionFailure.AUTHENTICATION_FAILED);
    }

    @Test
    void detectsDataAppendedAfterTheEnd() {
        byte[] encrypted = encrypt(randomBytes(2 * CHUNK, 4));
        byte[] longer = Arrays.copyOf(encrypted, encrypted.length + 40);

        assertFailure(longer, PASSWORD, DecryptionFailure.TRAILING_DATA);
    }

    @Test
    void detectsSwappedChunks() {
        byte[] encrypted = encrypt(randomBytes(3 * CHUNK, 5));
        int header = headerLength(encrypted);
        int size = StreamChunks.SEALED_CHUNK_SIZE;
        byte[] swapped = encrypted.clone();
        System.arraycopy(encrypted, header, swapped, header + size, size);
        System.arraycopy(encrypted, header + size, swapped, header, size);

        assertFailure(swapped, PASSWORD, DecryptionFailure.AUTHENTICATION_FAILED);
    }

    @Test
    void anyChangeToTheHeaderBreaksTheKey() {
        byte[] encrypted = encrypt(randomBytes(100, 6));

        for (int i = 7; i < headerLength(encrypted); i++) {
            byte[] tampered = encrypted.clone();
            tampered[i] ^= 0x01;
            assertThatThrownBy(() -> decrypt(tampered)).as("byte %d", i).isInstanceOf(DecryptionException.class);
        }
    }

    @Test
    void explainsInputThatIsNotAPasswordStream() {
        assertFailure("hello world".getBytes(), PASSWORD, DecryptionFailure.NOT_AN_ENVELOPE);
        assertFailure("EACL".getBytes(), PASSWORD, DecryptionFailure.MALFORMED);
        byte[] encrypted = encrypt(new byte[10]);
        assertFailure(Arrays.copyOf(encrypted, headerLength(encrypted)), PASSWORD, DecryptionFailure.MALFORMED);
    }

    @Test
    void leavesTheCallersStreamsOpen() throws Exception {
        TrackingOutput out = new TrackingOutput();

        encryption.encrypt(new ByteArrayInputStream(new byte[10]), out, PASSWORD);

        assertThat(out.closed).isFalse();
    }

    private byte[] encrypt(byte[] plaintext) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            encryption.encrypt(new ByteArrayInputStream(plaintext), out, PASSWORD);
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] decrypt(byte[] encrypted) throws IOException, DecryptionException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PasswordFileEncryption.decrypt(new ByteArrayInputStream(encrypted), out, PASSWORD);
        return out.toByteArray();
    }

    private static void assertFailure(byte[] encrypted, char[] password, DecryptionFailure expected) {
        assertThatThrownBy(() -> PasswordFileEncryption.decrypt(new ByteArrayInputStream(encrypted), new ByteArrayOutputStream(), password))
                .isInstanceOfSatisfying(DecryptionException.class, e -> assertThat(e.failure()).isEqualTo(expected));
    }

    private static int headerLength(byte[] encrypted) {
        return encrypted[6] == 0x02 ? 4 + 3 + 9 + 16 + 16 : 4 + 3 + 4 + 16 + 16;
    }

    private static int headerLengthFor() {
        return 4 + 3 + 9 + 16 + 16;
    }

    private static byte[] randomBytes(int size, long seed) {
        byte[] bytes = new byte[size];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }

    private static final class PatternStream extends InputStream {
        private final long size;
        private long position;

        PatternStream(long size) {
            this.size = size;
        }

        @Override
        public int read() {
            return position < size ? (int) (position++ & 0x7F) : -1;
        }
    }

    private static final class CountingSink extends OutputStream {
        long count;

        @Override
        public void write(int b) {
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) {
            count += len;
        }
    }

    private static final class TrackingOutput extends ByteArrayOutputStream {
        boolean closed;

        @Override
        public void close() {
            closed = true;
        }
    }
}
