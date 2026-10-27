package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.cli.io.PasswordSource;
import com.danyastry.encryption.cli.io.SafeOutput;
import com.danyastry.encryption.cli.option.InputOption;
import com.danyastry.encryption.cli.option.KeyOption;
import com.danyastry.encryption.cli.option.OutputOption;
import com.danyastry.encryption.core.acl.RecipientFiles;
import com.danyastry.encryption.core.acl.RecipientHeader;
import com.danyastry.encryption.core.keys.Identity;
import com.danyastry.encryption.core.stream.PasswordFileEncryption;
import com.danyastry.encryption.core.stream.PasswordStreamHeader;
import com.danyastry.encryption.core.util.Secrets;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(name = "decrypt", description = "Decrypt a file made with a password or for your key. With -o the file appears only after it is fully verified; on standard output, check the exit code before trusting the data.")
public final class DecryptCommand implements Callable<Integer> {

    @Mixin
    private InputOption input;

    @Mixin
    private OutputOption output;

    @ArgGroup(exclusive = false)
    private KeyOption key;

    @Option(names = "--password-file", paramLabel = "FILE", description = "Read the password from the first line of FILE.")
    private Path passwordFile;

    @Override
    public Integer call() throws Exception {
        try (InputStream in = Inputs.open(input.file, System.in)) {
            int type = Inputs.peekType(in);
            if (type == RecipientHeader.TYPE_RECIPIENT_STREAM) {
                if (key == null) {
                    throw new IllegalArgumentException("This file was encrypted for recipients; give your key with --key");
                }
                Identity identity = key.load();
                try (SafeOutput out = SafeOutput.to(output.file, output.force, System.out)) {
                    RecipientFiles.decrypt(in, out.stream(), identity.encryption());
                    out.commit();
                }
            } else if (type == PasswordStreamHeader.TYPE_PASSWORD_STREAM) {
                char[] password = PasswordSource.read(passwordFile, "password", false);
                try (SafeOutput out = SafeOutput.to(output.file, output.force, System.out)) {
                    PasswordFileEncryption.decrypt(in, out.stream(), password);
                    out.commit();
                } finally {
                    Secrets.wipe(password);
                }
            } else {
                throw new IllegalArgumentException("The input is not a file encrypted by this tool");
            }
        }
        return 0;
    }
}
