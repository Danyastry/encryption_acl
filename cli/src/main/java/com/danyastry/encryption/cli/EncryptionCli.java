package com.danyastry.encryption.cli;

import com.danyastry.encryption.cli.command.AccessCommand;
import com.danyastry.encryption.cli.command.DecryptCommand;
import com.danyastry.encryption.cli.command.EncryptCommand;
import com.danyastry.encryption.cli.command.FingerprintCommand;
import com.danyastry.encryption.cli.command.KeygenCommand;
import com.danyastry.encryption.cli.command.RekeyCommand;
import com.danyastry.encryption.cli.command.SignCommand;
import com.danyastry.encryption.cli.command.VerifyCommand;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
        name = "encryption",
        mixinStandardHelpOptions = true,
        version = "encryption 0.1.0",
        description = "Encrypt, decrypt and sign data with modern authenticated cryptography.",
        subcommands = {
            KeygenCommand.class,
            EncryptCommand.class,
            DecryptCommand.class,
            AccessCommand.class,
            RekeyCommand.class,
            SignCommand.class,
            VerifyCommand.class,
            FingerprintCommand.class,
        })
public final class EncryptionCli implements Runnable {

    @CommandLine.Spec
    private CommandLine.Model.CommandSpec spec;

    public static void main(String[] args) {
        System.exit(commandLine().execute(args));
    }

    public static CommandLine commandLine() {
        return new CommandLine(new EncryptionCli()).setExecutionExceptionHandler(new ErrorHandler());
    }

    @Override
    public void run() {
        spec.commandLine().usage(spec.commandLine().getOut());
    }
}
