package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.cli.io.SafeOutput;
import com.danyastry.encryption.cli.option.InputOption;
import com.danyastry.encryption.cli.option.KeyOption;
import com.danyastry.encryption.cli.option.OutputOption;
import com.danyastry.encryption.core.keys.Identity;
import com.danyastry.encryption.core.signature.Signatures;
import java.io.InputStream;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;

@Command(name = "sign", description = "Write a detached Ed25519 signature for a file.")
public final class SignCommand implements Callable<Integer> {

    @Mixin
    private InputOption input;

    @Mixin
    private OutputOption output;

    @Mixin
    private KeyOption key;

    @Override
    public Integer call() throws Exception {
        Identity identity = key.load();
        try (InputStream in = Inputs.open(input.file, System.in); SafeOutput out = SafeOutput.to(output.file, output.force, System.out)) {
            out.stream().write(Signatures.signStream(in, identity.signing()));
            out.commit();
        }
        return 0;
    }
}
