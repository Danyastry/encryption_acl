package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.cli.io.SafeOutput;
import com.danyastry.encryption.cli.option.InputOption;
import com.danyastry.encryption.cli.option.KeyOption;
import com.danyastry.encryption.cli.option.OutputOption;
import com.danyastry.encryption.cli.option.RecipientOption;
import com.danyastry.encryption.core.acl.RecipientFiles;
import com.danyastry.encryption.core.keys.Identity;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(name = "rekey", description = "Re-encrypt under a brand-new file key for exactly these recipients.")
public final class RekeyCommand implements Callable<Integer> {

    @Mixin
    private InputOption input;

    @Mixin
    private OutputOption output;

    @Mixin
    private KeyOption key;

    @Option(names = {"-r", "--recipient"}, paramLabel = "PUB", required = true, description = "Public key file that keeps access. Repeat for several.")
    private List<Path> recipients;

    @Override
    public Integer call() throws Exception {
        Identity identity = key.load();
        List<byte[]> keys = RecipientOption.load(recipients);
        try (InputStream in = Inputs.open(input.file, System.in); SafeOutput out = SafeOutput.to(output.file, output.force, System.out)) {
            new RecipientFiles().rekey(in, out.stream(), identity.encryption(), keys);
            out.commit();
        }
        return 0;
    }
}
