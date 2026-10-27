package com.danyastry.encryption.cli.command;

import picocli.CommandLine.Command;

@Command(
        name = "access",
        description = "See and change who can open a file encrypted for recipients.",
        subcommands = {AccessListCommand.class, AccessAddCommand.class, AccessRemoveCommand.class})
public final class AccessCommand {
}
