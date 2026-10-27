package com.danyastry.encryption.cli.io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public final class SafeOutput implements AutoCloseable {

    private final Path target;
    private final Path temporary;
    private final OutputStream stream;
    private boolean committed;

    private SafeOutput(Path target, Path temporary, OutputStream stream) {
        this.target = target;
        this.temporary = temporary;
        this.stream = stream;
    }

    public static SafeOutput to(Path target, boolean overwrite, OutputStream standardOutput) throws IOException {
        if (target == null) {
            return new SafeOutput(null, null, new FilterOutputStream(standardOutput) {
                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    out.write(b, off, len);
                }

                @Override
                public void close() throws IOException {
                    flush();
                }
            });
        }
        if (Files.exists(target) && !overwrite) {
            throw new IllegalArgumentException(target + " already exists; use --force to replace it");
        }
        Path directory = target.toAbsolutePath().getParent();
        Path temporary = Files.createTempFile(directory, "." + target.getFileName(), ".part");
        return new SafeOutput(target, temporary, Files.newOutputStream(temporary));
    }

    public OutputStream stream() {
        return stream;
    }

    public void commit() throws IOException {
        stream.close();
        if (temporary != null) {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
        committed = true;
    }

    @Override
    public void close() throws IOException {
        if (committed) {
            return;
        }
        stream.close();
        if (temporary != null) {
            Files.deleteIfExists(temporary);
        }
    }
}
