package com.danyastry.encryption.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
        name = "encryption",
        mixinStandardHelpOptions = true,
        version = "encryption 0.1.0",
        description = "Encrypt, decrypt and sign data with modern authenticated cryptography.")
public final class EncryptionCli implements Runnable {

    @CommandLine.Spec
    private CommandLine.Model.CommandSpec spec;

    public static void main(String[] args) {
        System.exit(new CommandLine(new EncryptionCli()).execute(args));
    }

    @Override
    public void run() {
        spec.commandLine().usage(spec.commandLine().getOut());
    }
}
