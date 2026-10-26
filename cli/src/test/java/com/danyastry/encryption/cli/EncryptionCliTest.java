package com.danyastry.encryption.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.PrintWriter;
import java.io.StringWriter;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class EncryptionCliTest {

    @Test
    void printsItsVersion() {
        StringWriter out = new StringWriter();
        CommandLine command = new CommandLine(new EncryptionCli()).setOut(new PrintWriter(out));

        int exit = command.execute("--version");

        assertThat(exit).isZero();
        assertThat(out.toString()).contains("encryption 0.1.0");
    }

    @Test
    void showsUsageWithoutArguments() {
        StringWriter out = new StringWriter();
        CommandLine command = new CommandLine(new EncryptionCli()).setOut(new PrintWriter(out));

        int exit = command.execute();

        assertThat(exit).isZero();
        assertThat(out.toString()).contains("Usage: encryption");
    }
}
