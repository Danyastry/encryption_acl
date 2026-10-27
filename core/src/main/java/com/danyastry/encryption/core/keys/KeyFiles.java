package com.danyastry.encryption.core.keys;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.password.PasswordEncryption;
import com.danyastry.encryption.core.signature.Ed25519KeyPair;
import com.danyastry.encryption.core.util.Secrets;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class KeyFiles {

    public static final String PUBLIC_LABEL = "EACL PUBLIC KEY";
    public static final String PRIVATE_LABEL = "EACL ENCRYPTED PRIVATE KEY";
    public static final String UNPROTECTED_LABEL = "EACL UNENCRYPTED PRIVATE KEY";

    private static final int VERSION = 1;
    private static final int KEY_BYTES = 1 + 2 * X25519KeyPair.KEY_LENGTH;
    private static final Pattern BLOCK = Pattern.compile("-----BEGIN ([A-Z ]+)-----\\s*([A-Za-z0-9+/=\\s]+?)\\s*-----END \\1-----");

    private KeyFiles() {
    }

    public static String encodePublic(PublicIdentity identity) {
        return "# encryption_acl public key\n# fingerprint " + identity.fingerprint() + "\n"
                + armor(PUBLIC_LABEL, pack(identity.encryptionKey(), identity.signingKey()));
    }

    public static PublicIdentity parsePublic(String text) throws KeyFileException {
        byte[] bytes = dearmor(text, PUBLIC_LABEL);
        byte[][] keys = unpack(bytes);
        return new PublicIdentity(keys[0], keys[1]);
    }

    public static String encodePrivate(Identity identity, PasswordEncryption protection, char[] passphrase) {
        byte[] secret = pack(identity.encryption().privateKey(), identity.signing().privateKey());
        try {
            return "# encryption_acl private key, keep it secret\n# fingerprint " + identity.fingerprint() + "\n"
                    + armor(PRIVATE_LABEL, protection.encrypt(secret, passphrase));
        } finally {
            Secrets.wipe(secret);
        }
    }

    public static String encodeUnprotectedPrivate(Identity identity) {
        byte[] secret = pack(identity.encryption().privateKey(), identity.signing().privateKey());
        try {
            return "# encryption_acl private key without a passphrase, keep it secret\n# fingerprint " + identity.fingerprint() + "\n"
                    + armor(UNPROTECTED_LABEL, secret);
        } finally {
            Secrets.wipe(secret);
        }
    }

    public static boolean isProtected(String text) {
        return text.contains("-----BEGIN " + PRIVATE_LABEL + "-----");
    }

    public static Identity parsePrivate(String text, char[] passphrase) throws KeyFileException, DecryptionException {
        byte[] secret = isProtected(text)
                ? PasswordEncryption.decrypt(dearmor(text, PRIVATE_LABEL), passphrase == null ? new char[0] : passphrase)
                : dearmor(text, UNPROTECTED_LABEL);
        try {
            byte[][] keys = unpack(secret);
            return new Identity(X25519KeyPair.fromPrivateKey(keys[0]), Ed25519KeyPair.fromPrivateKey(keys[1]));
        } finally {
            Secrets.wipe(secret);
        }
    }

    private static byte[] pack(byte[] first, byte[] second) {
        byte[] out = new byte[KEY_BYTES];
        out[0] = VERSION;
        System.arraycopy(first, 0, out, 1, first.length);
        System.arraycopy(second, 0, out, 1 + first.length, second.length);
        return out;
    }

    private static byte[][] unpack(byte[] bytes) throws KeyFileException {
        if (bytes.length != KEY_BYTES || bytes[0] != VERSION) {
            throw new KeyFileException("Unsupported key file version or length");
        }
        return new byte[][] {
            Arrays.copyOfRange(bytes, 1, 1 + X25519KeyPair.KEY_LENGTH),
            Arrays.copyOfRange(bytes, 1 + X25519KeyPair.KEY_LENGTH, KEY_BYTES),
        };
    }

    private static String armor(String label, byte[] bytes) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(bytes);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static byte[] dearmor(String text, String expectedLabel) throws KeyFileException {
        Matcher matcher = BLOCK.matcher(text);
        if (!matcher.find()) {
            throw new KeyFileException("No encryption_acl key block found");
        }
        if (!matcher.group(1).equals(expectedLabel)) {
            throw new KeyFileException("Expected a " + expectedLabel.toLowerCase() + ", found a " + matcher.group(1).toLowerCase());
        }
        try {
            return Base64.getMimeDecoder().decode(matcher.group(2));
        } catch (IllegalArgumentException e) {
            throw new KeyFileException("The key block is not valid Base64");
        }
    }
}
