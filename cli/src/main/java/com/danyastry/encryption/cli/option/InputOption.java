package com.danyastry.encryption.cli.option;

import java.nio.file.Path;
import picocli.CommandLine.Option;

public final class InputOption {

    @Option(names = {"-i", "--input"}, paramLabel = "FILE", description = "Read from FILE instead of standard input.")
    public Path file;
}
