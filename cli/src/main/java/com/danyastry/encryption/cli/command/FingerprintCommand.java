package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.core.keys.KeyFiles;
import com.danyastry.encryption.core.keys.PublicIdentity;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

@Command(name = "fingerprint", description = "Show the fingerprints of a public key file, to compare with its owner.")
public final class FingerprintCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Parameters(paramLabel = "PUB", description = "Public key file.")
    private Path publicKey;

    @Override
    public Integer call() throws Exception {
        PublicIdentity identity = KeyFiles.parsePublic(Inputs.text(publicKey));
        spec.commandLine().getOut().printf("Encryption %s%nSigning    %s%n", identity.fingerprint(), identity.signingFingerprint());
        return 0;
    }
}
