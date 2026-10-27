package com.danyastry.encryption.cli.option;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.core.keys.KeyFileException;
import com.danyastry.encryption.core.keys.KeyFiles;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class RecipientOption {

    private RecipientOption() {
    }

    public static List<byte[]> load(List<Path> files) throws IOException, KeyFileException {
        List<byte[]> keys = new ArrayList<>();
        for (Path file : files) {
            keys.add(KeyFiles.parsePublic(Inputs.text(file)).encryptionKey());
        }
        return keys;
    }
}
