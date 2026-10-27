package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.cli.io.PasswordSource;
import com.danyastry.encryption.cli.io.SafeOutput;
import com.danyastry.encryption.cli.option.InputOption;
import com.danyastry.encryption.cli.option.OutputOption;
import com.danyastry.encryption.cli.option.RecipientOption;
import com.danyastry.encryption.core.acl.RecipientFiles;
import com.danyastry.encryption.core.kdf.Argon2idParameters;
import com.danyastry.encryption.core.kdf.KdfParameters;
import com.danyastry.encryption.core.kdf.Pbkdf2Parameters;
import com.danyastry.encryption.core.stream.PasswordFileEncryption;
import com.danyastry.encryption.core.util.Secrets;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(name = "encrypt", description = "Encrypt with a password, or for one or more recipients' public keys.")
public final class EncryptCommand implements Callable<Integer> {

    @Mixin
    private InputOption input;

    @Mixin
    private OutputOption output;

    @Option(names = {"-r", "--recipient"}, paramLabel = "PUB", description = "Encrypt for this public key file. Repeat for several recipients.")
    private List<Path> recipients = new ArrayList<>();

    @Option(names = {"-p", "--password"}, description = "Encrypt with a password instead of public keys.")
    private boolean password;

    @Option(names = "--password-file", paramLabel = "FILE", description = "Read the password from the first line of FILE.")
    private Path passwordFile;

    @Option(names = "--kdf", paramLabel = "KDF", description = "Password key derivation: ${COMPLETION-CANDIDATES} (default: ${DEFAULT-VALUE}).")
    private Kdf kdf = Kdf.argon2id;

    @Override
    public Integer call() throws Exception {
        boolean usePassword = password || passwordFile != null;
        if (usePassword == !recipients.isEmpty()) {
            throw new IllegalArgumentException("Use either --password or at least one --recipient");
        }
        List<byte[]> keys = usePassword ? List.of() : RecipientOption.load(recipients);
        char[] secret = usePassword ? PasswordSource.read(passwordFile, "password", true) : null;
        try (InputStream in = Inputs.open(input.file, System.in); SafeOutput out = SafeOutput.to(output.file, output.force, System.out)) {
            if (usePassword) {
                new PasswordFileEncryption(kdf.parameters()).encrypt(in, out.stream(), secret);
            } else {
                new RecipientFiles().encrypt(in, out.stream(), keys);
            }
            out.commit();
        } finally {
            Secrets.wipe(secret);
        }
        return 0;
    }

    enum Kdf {
        argon2id,
        pbkdf2;

        KdfParameters parameters() {
            return this == argon2id ? Argon2idParameters.recommended() : Pbkdf2Parameters.recommended();
        }
    }
}
