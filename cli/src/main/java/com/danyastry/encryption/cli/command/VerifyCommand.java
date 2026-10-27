package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.cli.option.InputOption;
import com.danyastry.encryption.core.keys.KeyFiles;
import com.danyastry.encryption.core.keys.PublicIdentity;
import com.danyastry.encryption.core.signature.Signatures;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

@Command(name = "verify", description = "Check that a file was signed by the owner of a public key.")
public final class VerifyCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Mixin
    private InputOption input;

    @Option(names = {"-s", "--signature"}, paramLabel = "SIG", required = true, description = "Signature file made by 'sign'.")
    private Path signature;

    @Option(names = {"-p", "--public-key"}, paramLabel = "PUB", required = true, description = "Public key file of the expected signer.")
    private Path publicKey;

    @Override
    public Integer call() throws Exception {
        PublicIdentity signer = KeyFiles.parsePublic(Inputs.text(publicKey));
        try (InputStream in = Inputs.open(input.file, System.in)) {
            Signatures.verifyStream(in, Files.readAllBytes(signature), signer.signingKey());
        }
        spec.commandLine().getOut().printf("Good signature from %s%n", signer.fingerprint());
        return 0;
    }
}
