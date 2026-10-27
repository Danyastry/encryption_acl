package com.danyastry.encryption.cli.command;

import com.danyastry.encryption.cli.io.Inputs;
import com.danyastry.encryption.cli.option.InputOption;
import com.danyastry.encryption.core.acl.RecipientFiles;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

@Command(name = "list", description = "Print the fingerprints of everyone who can open the file.")
public final class AccessListCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Mixin
    private InputOption input;

    @Override
    public Integer call() throws Exception {
        try (InputStream in = Inputs.open(input.file, System.in)) {
            List<String> recipients = RecipientFiles.recipients(in);
            PrintWriter out = spec.commandLine().getOut();
            recipients.forEach(out::println);
            out.printf("%d recipient%s (not verified until someone opens the file)%n", recipients.size(), recipients.size() == 1 ? "" : "s");
            out.flush();
        }
        return 0;
    }
}
