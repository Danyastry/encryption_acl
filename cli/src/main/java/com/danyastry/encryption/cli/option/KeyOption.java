package com.danyastry.encryption.cli.option;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.cli.io.PasswordSource;
import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.keys.Identity;
import com.danyastry.encryption.core.keys.KeyFileException;
import com.danyastry.encryption.core.keys.KeyFiles;
import com.danyastry.encryption.core.util.Secrets;
import java.io.IOException;
import java.nio.file.Path;
import picocli.CommandLine.Option;

public final class KeyOption {

    @Option(names = {"-k", "--key"}, paramLabel = "KEY", required = true, description = "Your private key file.")
    public Path file;

    @Option(names = "--passphrase-file", paramLabel = "FILE", description = "Read the key passphrase from the first line of FILE.")
    public Path passphraseFile;

    public Identity load() throws IOException, KeyFileException, DecryptionException {
        String text = Inputs.text(file);
        if (!KeyFiles.isProtected(text)) {
            return KeyFiles.parsePrivate(text, null);
        }
        char[] passphrase = PasswordSource.read(passphraseFile, "key passphrase", false);
        try {
            return KeyFiles.parsePrivate(text, passphrase);
        } finally {
            Secrets.wipe(passphrase);
        }
    }
}
