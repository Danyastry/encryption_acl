package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.PasswordSource;
import com.danyastry.encryption.core.keys.Identity;
import com.danyastry.encryption.core.keys.KeyFiles;
import com.danyastry.encryption.core.password.PasswordEncryption;
import com.danyastry.encryption.core.util.Secrets;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

@Command(name = "keygen", description = "Create a key pair: NAME.key (private) and NAME.pub (public).")
public final class KeygenCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Option(names = {"-o", "--output"}, paramLabel = "NAME", required = true, description = "Base name of the key files.")
    private Path name;

    @Option(names = "--no-passphrase", description = "Store the private key without a passphrase.")
    private boolean noPassphrase;

    @Option(names = "--passphrase-file", paramLabel = "FILE", description = "Read the new passphrase from the first line of FILE.")
    private Path passphraseFile;

    @Option(names = {"-f", "--force"}, description = "Replace existing key files.")
    private boolean force;

    @Override
    public Integer call() throws Exception {
        Path privateFile = Path.of(name + ".key");
        Path publicFile = Path.of(name + ".pub");
        for (Path file : new Path[] {privateFile, publicFile}) {
            if (Files.exists(file) && !force) {
                throw new IllegalArgumentException(file + " already exists; use --force to replace it");
            }
        }
        Identity identity = Identity.generate(new SecureRandom());
        String privateText;
        if (noPassphrase) {
            privateText = KeyFiles.encodeUnprotectedPrivate(identity);
        } else {
            char[] passphrase = PasswordSource.read(passphraseFile, "new key passphrase", true);
            try {
                privateText = KeyFiles.encodePrivate(identity, PasswordEncryption.recommended(), passphrase);
            } finally {
                Secrets.wipe(passphrase);
            }
        }
        writePrivate(privateFile, privateText);
        Files.writeString(publicFile, KeyFiles.encodePublic(identity.publicIdentity()), StandardCharsets.UTF_8);
        spec.commandLine().getOut().printf("Created %s and %s%nFingerprint %s%n", privateFile, publicFile, identity.fingerprint());
        return 0;
    }

    private static void writePrivate(Path file, String text) throws IOException {
        Files.deleteIfExists(file);
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.createFile(file);
        }
        Files.writeString(file, text, StandardCharsets.UTF_8);
    }
}
