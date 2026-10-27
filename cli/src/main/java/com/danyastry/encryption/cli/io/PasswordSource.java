package com.danyastry.encryption.cli.io;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class PasswordSource {

    private PasswordSource() {
    }

    public static char[] read(Path file, String prompt, boolean confirm) throws IOException {
        if (file != null) {
            return fromFile(file);
        }
        Console console = System.console();
        if (console == null) {
            throw new IllegalArgumentException("No terminal to ask for the " + prompt + "; pass it with a file option instead");
        }
        char[] first = console.readPassword("%s: ", capitalize(prompt));
        if (first == null || first.length == 0) {
            throw new IllegalArgumentException("The " + prompt + " cannot be empty");
        }
        if (confirm) {
            char[] second = console.readPassword("Repeat the %s: ", prompt);
            boolean same = Arrays.equals(first, second);
            Arrays.fill(second == null ? new char[0] : second, '\0');
            if (!same) {
                Arrays.fill(first, '\0');
                throw new IllegalArgumentException("The two " + prompt + "s do not match");
            }
        }
        return first;
    }

    private static char[] fromFile(Path file) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line = reader.readLine();
            if (line == null || line.isEmpty()) {
                throw new IllegalArgumentException(file + " does not contain a password on its first line");
            }
            return line.toCharArray();
        }
    }

    private static String capitalize(String text) {
        return Character.toUpperCase(text.charAt(0)) + text.substring(1);
    }
}
