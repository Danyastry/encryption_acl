package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.cli.io.SafeOutput;
import com.danyastry.encryption.cli.option.InputOption;
import com.danyastry.encryption.cli.option.KeyOption;
import com.danyastry.encryption.cli.option.OutputOption;
import com.danyastry.encryption.core.acl.RecipientFiles;
import com.danyastry.encryption.core.keys.Identity;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

@Command(name = "remove", description = "Take people off the file. Use rekey as well if they may have kept the old file key.")
public final class AccessRemoveCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Mixin
    private InputOption input;

    @Mixin
    private OutputOption output;

    @Mixin
    private KeyOption key;

    @Option(names = "--fingerprint", paramLabel = "FP", required = true, description = "Fingerprint to remove, as shown by 'access list'.")
    private List<String> fingerprints;

    @Override
    public Integer call() throws Exception {
        Identity identity = key.load();
        try (InputStream in = Inputs.open(input.file, System.in); SafeOutput out = SafeOutput.to(output.file, output.force, System.out)) {
            new RecipientFiles().changeRecipients(in, out.stream(), identity.encryption(), List.of(), fingerprints);
            out.commit();
        }
        spec.commandLine().getErr().println("Removed. Anyone who saved the old file key can still read old copies; run rekey to cut them off.");
        return 0;
    }
}
