package com.danyastry.encryption.core.stream;

import com.danyastry.encryption.core.util.Secrets;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

public final class EncryptingOutputStream extends FilterOutputStream {

    private final byte[] key;
    private final byte[] buffer = new byte[StreamChunks.CHUNK_SIZE];
    private int buffered;
    private long counter;
    private boolean closed;

    public EncryptingOutputStream(OutputStream out, byte[] payloadKey) {
        super(out);
        this.key = payloadKey.clone();
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] data, int offset, int length) throws IOException {
        if (closed) {
            throw new IOException("Stream is closed");
        }
        int end = offset + length;
        while (offset < end) {
            if (buffered == buffer.length) {
                emit(false);
            }
            int take = Math.min(buffer.length - buffered, end - offset);
            System.arraycopy(data, offset, buffer, buffered, take);
            buffered += take;
            offset += take;
        }
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    public void finish() throws IOException {
        if (closed) {
            return;
        }
        try {
            emit(true);
            out.flush();
        } finally {
            closed = true;
            Secrets.wipe(key);
            Arrays.fill(buffer, (byte) 0);
        }
    }

    @Override
    public void close() throws IOException {
        try {
            finish();
        } finally {
            out.close();
        }
    }

    private void emit(boolean last) throws IOException {
        out.write(StreamChunks.seal(key, counter, last, Arrays.copyOf(buffer, buffered)));
        counter++;
        buffered = 0;
    }
}
