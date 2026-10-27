package com.danyastry.encryption.core.stream;

import com.danyastry.encryption.core.aead.ChaCha20Poly1305;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.util.Secrets;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

public final class DecryptingInputStream extends InputStream {

    private final InputStream in;
    private final byte[] key;
    private final byte[] sealed = new byte[StreamChunks.SEALED_CHUNK_SIZE];
    private int lookahead = -1;
    private byte[] plaintext = new byte[0];
    private int position;
    private long counter;
    private boolean finished;

    public DecryptingInputStream(InputStream in, byte[] payloadKey) {
        this.in = in;
        this.key = payloadKey.clone();
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        return read(one, 0, 1) == -1 ? -1 : one[0] & 0xFF;
    }

    @Override
    public int read(byte[] target, int offset, int length) throws IOException {
        while (position == plaintext.length) {
            if (finished) {
                return -1;
            }
            nextChunk();
        }
        int take = Math.min(length, plaintext.length - position);
        System.arraycopy(plaintext, position, target, offset, take);
        position += take;
        return take;
    }

    @Override
    public void close() throws IOException {
        Secrets.wipe(key);
        in.close();
    }

    private void nextChunk() throws IOException {
        int filled = 0;
        if (lookahead >= 0) {
            sealed[filled++] = (byte) lookahead;
        }
        while (filled < sealed.length) {
            int count = in.read(sealed, filled, sealed.length - filled);
            if (count < 0) {
                break;
            }
            filled += count;
        }
        lookahead = filled == sealed.length ? in.read() : -1;
        boolean last = lookahead < 0;
        if (filled < ChaCha20Poly1305.TAG_LENGTH) {
            throw new StreamDecryptionException(counter == 0 ? DecryptionFailure.MALFORMED : DecryptionFailure.TRUNCATED);
        }
        byte[] chunk = Arrays.copyOf(sealed, filled);
        try {
            plaintext = StreamChunks.open(key, counter, last, chunk);
        } catch (AEADBadTagException e) {
            throw new StreamDecryptionException(diagnose(chunk, last));
        }
        if (last && plaintext.length == 0 && counter > 0) {
            throw new StreamDecryptionException(DecryptionFailure.AUTHENTICATION_FAILED);
        }
        position = 0;
        counter++;
        finished = last;
    }

    private DecryptionFailure diagnose(byte[] chunk, boolean last) {
        try {
            StreamChunks.open(key, counter, !last, chunk);
            return last ? DecryptionFailure.TRUNCATED : DecryptionFailure.TRAILING_DATA;
        } catch (AEADBadTagException e) {
            return DecryptionFailure.AUTHENTICATION_FAILED;
        }
    }
}
