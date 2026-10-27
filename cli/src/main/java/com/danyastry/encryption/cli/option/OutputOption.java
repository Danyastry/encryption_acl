package com.danyastry.encryption.cli.option;

import java.nio.file.Path;
import picocli.CommandLine.Option;

public final class OutputOption {

    @Option(names = {"-o", "--output"}, paramLabel = "FILE", description = "Write to FILE instead of standard output.")
    public Path file;

    @Option(names = {"-f", "--force"}, description = "Replace the output file if it exists.")
    public boolean force;
}
