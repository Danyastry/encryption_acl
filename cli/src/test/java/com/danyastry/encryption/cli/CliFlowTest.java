package com.danyastry.encryption.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class CliFlowTest {

    @TempDir
    Path dir;

    private Path secret;
    private Path password;
    private byte[] content;

    @BeforeEach
    void setUp() throws IOException {
        content = new byte[200_000];
        new Random(1).nextBytes(content);
        secret = Files.write(dir.resolve("report.bin"), content);
        password = Files.writeString(dir.resolve("password.txt"), "correct horse battery\n");
    }

    @Test
    void encryptsAndDecryptsWithAPassword() throws IOException {
        Path sealed = dir.resolve("report.eacl");
        Path opened = dir.resolve("report.out");

        assertThat(run("encrypt", "-i", secret, "-o", sealed, "--password-file", password, "--kdf", "pbkdf2").exit).isZero();
        assertThat(run("decrypt", "-i", sealed, "-o", opened, "--password-file", password).exit).isZero();

        assertThat(Files.readAllBytes(opened)).isEqualTo(content);
        assertThat(Files.readAllBytes(sealed)).isNotEqualTo(content);
    }

    @Test
    void aWrongPasswordLeavesNoOutputBehind() throws IOException {
        Path sealed = dir.resolve("report.eacl");
        Path opened = dir.resolve("report.out");
        run("encrypt", "-i", secret, "-o", sealed, "--password-file", password, "--kdf", "pbkdf2");
        Path wrong = Files.writeString(dir.resolve("wrong.txt"), "nope\n");

        Result result = run("decrypt", "-i", sealed, "-o", opened, "--password-file", wrong);

        assertThat(result.exit).isEqualTo(ErrorHandler.FAILURE);
        assertThat(result.err).contains("Wrong password, or the data was changed");
        assertThat(opened).doesNotExist();
        assertThat(partFiles().toList()).isEmpty();
    }

    @Test
    void aTruncatedFileLeavesNoOutputBehind() throws IOException {
        Path sealed = dir.resolve("report.eacl");
        run("encrypt", "-i", secret, "-o", sealed, "--password-file", password, "--kdf", "pbkdf2");
        byte[] bytes = Files.readAllBytes(sealed);
        Path cut = Files.write(dir.resolve("cut.eacl"), Arrays.copyOf(bytes, bytes.length - 5000));
        Path opened = dir.resolve("cut.out");

        Result result = run("decrypt", "-i", cut, "-o", opened, "--password-file", password);

        assertThat(result.exit).isEqualTo(ErrorHandler.FAILURE);
        assertThat(opened).doesNotExist();
        assertThat(partFiles().toList()).isEmpty();
    }

    @Test
    void sharesAFileWithSeveralPeopleAndChangesWhoHasAccess() throws IOException {
        keygen("alice");
        keygen("bob");
        keygen("carol");
        Path sealed = dir.resolve("shared.eacl");

        assertThat(run("encrypt", "-i", secret, "-o", sealed, "-r", pub("alice"), "-r", pub("bob")).exit).isZero();
        assertThat(decryptWith("bob", sealed)).isEqualTo(content);
        assertThat(run("decrypt", "-i", sealed, "-o", dir.resolve("carol.out"), "-k", key("carol")).err).contains("not one of the recipients");

        Path withCarol = dir.resolve("with-carol.eacl");
        assertThat(run("access", "add", "-i", sealed, "-o", withCarol, "-k", key("alice"), "-r", pub("carol")).exit).isZero();
        assertThat(decryptWith("carol", withCarol)).isEqualTo(content);

        Result listed = run("access", "list", "-i", withCarol);
        assertThat(listed.out).contains(fingerprint("alice"), fingerprint("bob"), fingerprint("carol")).contains("3 recipients");

        Path withoutBob = dir.resolve("without-bob.eacl");
        Result removed = run("access", "remove", "-i", withCarol, "-o", withoutBob, "-k", key("alice"), "--fingerprint", fingerprint("bob"));
        assertThat(removed.exit).isZero();
        assertThat(removed.err).contains("run rekey");
        assertThat(run("decrypt", "-i", withoutBob, "-o", dir.resolve("bob2.out"), "-k", key("bob")).exit).isEqualTo(ErrorHandler.FAILURE);

        Path rekeyed = dir.resolve("rekeyed.eacl");
        assertThat(run("rekey", "-i", withoutBob, "-o", rekeyed, "-k", key("alice"), "-r", pub("alice"), "-r", pub("carol")).exit).isZero();
        assertThat(decryptWith("carol", rekeyed)).isEqualTo(content);
    }

    @Test
    void signsAndVerifiesFiles() throws IOException {
        keygen("alice");
        keygen("mallory");
        Path signature = dir.resolve("report.sig");

        assertThat(run("sign", "-i", secret, "-o", signature, "-k", key("alice")).exit).isZero();
        Result good = run("verify", "-i", secret, "-s", signature, "-p", pub("alice"));
        assertThat(good.exit).isZero();
        assertThat(good.out).contains("Good signature from " + fingerprint("alice"));

        assertThat(run("verify", "-i", secret, "-s", signature, "-p", pub("mallory")).err).contains("different key");
        content[0] ^= 1;
        Path changed = Files.write(dir.resolve("changed.bin"), content);
        assertThat(run("verify", "-i", changed, "-s", signature, "-p", pub("alice")).err).contains("does not match");
    }

    @Test
    void protectsPrivateKeysWithAPassphrase() throws IOException {
        Path passphrase = Files.writeString(dir.resolve("passphrase.txt"), "key passphrase\n");
        assertThat(run("keygen", "-o", dir.resolve("dana"), "--passphrase-file", passphrase).exit).isZero();
        Path sealed = dir.resolve("dana.eacl");
        run("encrypt", "-i", secret, "-o", sealed, "-r", pub("dana"));

        assertThat(Files.readString(key("dana"))).contains("EACL ENCRYPTED PRIVATE KEY");
        assertThat(run("decrypt", "-i", sealed, "-o", dir.resolve("dana.out"), "-k", key("dana"), "--passphrase-file", passphrase).exit).isZero();
        assertThat(run("decrypt", "-i", sealed, "-o", dir.resolve("dana2.out"), "-k", key("dana"), "--passphrase-file", password).exit)
                .isEqualTo(ErrorHandler.FAILURE);
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(key("dana")))).isEqualTo("rw-------");
        }
    }

    @Test
    void refusesToOverwriteWithoutForce() throws IOException {
        Path sealed = dir.resolve("report.eacl");
        run("encrypt", "-i", secret, "-o", sealed, "--password-file", password, "--kdf", "pbkdf2");

        Result again = run("encrypt", "-i", secret, "-o", sealed, "--password-file", password, "--kdf", "pbkdf2");

        assertThat(again.exit).isEqualTo(ErrorHandler.FAILURE);
        assertThat(again.err).contains("already exists");
        assertThat(run("encrypt", "-i", secret, "-o", sealed, "--password-file", password, "--kdf", "pbkdf2", "--force").exit).isZero();
    }

    @Test
    void explainsMisuse() throws IOException {
        keygen("alice");

        assertThat(run("encrypt", "-i", secret, "-o", dir.resolve("x"), "--password-file", password, "-r", pub("alice")).err)
                .contains("either --password or at least one --recipient");
        assertThat(run("decrypt", "-i", secret, "-o", dir.resolve("y"), "--password-file", password).err).contains("not a file encrypted by this tool");
        assertThat(run("decrypt", "-i", dir.resolve("missing.eacl"), "-o", dir.resolve("z"), "--password-file", password).err).contains("No such file");
        assertThat(run("encrypt", "-i", secret, "-o", dir.resolve("w"), "-r", key("alice")).err).contains("found a eacl unencrypted private key");
        assertThat(run("access").exit).isNotZero();
    }

    @Test
    void printsFingerprints() throws IOException {
        keygen("alice");

        Result result = run("fingerprint", pub("alice"));

        assertThat(result.out).contains("Encryption " + fingerprint("alice")).contains("Signing");
    }

    private void keygen(String name) {
        assertThat(run("keygen", "-o", dir.resolve(name), "--no-passphrase").exit).isZero();
    }

    private byte[] decryptWith(String name, Path sealed) throws IOException {
        Path out = dir.resolve(name + "-" + sealed.getFileName() + ".out");
        assertThat(run("decrypt", "-i", sealed, "-o", out, "-k", key(name)).exit).isZero();
        return Files.readAllBytes(out);
    }

    private String fingerprint(String name) {
        return run("fingerprint", pub(name)).out.lines().findFirst().orElseThrow().substring("Encryption ".length()).trim();
    }

    private Path key(String name) {
        return dir.resolve(name + ".key");
    }

    private Path pub(String name) {
        return dir.resolve(name + ".pub");
    }

    private Stream<Path> partFiles() throws IOException {
        return Files.list(dir).filter(path -> path.getFileName().toString().endsWith(".part"));
    }

    private Result run(Object... args) {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();
        CommandLine command = EncryptionCli.commandLine().setOut(new PrintWriter(out)).setErr(new PrintWriter(err));
        int exit = command.execute(Arrays.stream(args).map(String::valueOf).toArray(String[]::new));
        return new Result(exit, out.toString(), err.toString());
    }

    private record Result(int exit, String out, String err) {
    }
}
