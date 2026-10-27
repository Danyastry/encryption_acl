package com.danyastry.encryption.core.acl;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.hpke.DhkemX25519;
import com.danyastry.encryption.core.hpke.Encapsulation;
import com.danyastry.encryption.core.hpke.Hkdf;
import com.danyastry.encryption.core.hpke.Hpke;
import com.danyastry.encryption.core.hpke.HpkeMode;
import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.stream.DecryptingInputStream;
import com.danyastry.encryption.core.stream.EncryptingOutputStream;
import com.danyastry.encryption.core.stream.StreamChunks;
import com.danyastry.encryption.core.stream.StreamDecryptionException;
import com.danyastry.encryption.core.util.Fingerprint;
import com.danyastry.encryption.core.util.Secrets;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.AEADBadTagException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class RecipientFiles {

    public static final int FILE_KEY_LENGTH = 32;

    private static final byte[] FILE_KEY_INFO = "encryption_acl v1 file key".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] HEADER_MAC_INFO = "encryption_acl v1 header".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] NO_HEADER = new byte[0];
    private static final int COPY_BUFFER = 16 * 1024;

    private final SecureRandom random;

    public RecipientFiles(SecureRandom random) {
        this.random = random;
    }

    public RecipientFiles() {
        this(new SecureRandom());
    }

    public long encrypt(InputStream in, OutputStream out, List<byte[]> recipientPublicKeys) throws IOException {
        byte[] fileKey = new byte[FILE_KEY_LENGTH];
        byte[] payloadNonce = new byte[StreamChunks.PAYLOAD_NONCE_LENGTH];
        random.nextBytes(fileKey);
        random.nextBytes(payloadNonce);
        try {
            List<RecipientStanza> stanzas = new ArrayList<>(unique(recipientPublicKeys).values().stream().map(key -> wrap(fileKey, key)).toList());
            out.write(sign(new RecipientHeader(stanzas, payloadNonce, new byte[RecipientHeader.MAC_LENGTH]), fileKey).encode());
            byte[] payloadKey = StreamChunks.payloadKey(fileKey, payloadNonce, NO_HEADER);
            EncryptingOutputStream sealed = new EncryptingOutputStream(out, payloadKey);
            Secrets.wipe(payloadKey);
            long total = in.transferTo(sealed);
            sealed.finish();
            return total;
        } finally {
            Secrets.wipe(fileKey);
        }
    }

    public static InputStream open(InputStream in, X25519KeyPair me) throws IOException, DecryptionException {
        RecipientHeader header = RecipientHeader.read(in);
        byte[] fileKey = unlock(header, me);
        try {
            byte[] payloadKey = StreamChunks.payloadKey(fileKey, header.payloadNonce(), NO_HEADER);
            try {
                return new DecryptingInputStream(in, payloadKey, true);
            } finally {
                Secrets.wipe(payloadKey);
            }
        } finally {
            Secrets.wipe(fileKey);
        }
    }

    public static long decrypt(InputStream in, OutputStream out, X25519KeyPair me) throws IOException, DecryptionException {
        InputStream plaintext = open(in, me);
        try {
            byte[] buffer = new byte[COPY_BUFFER];
            long total = 0;
            for (int count; (count = plaintext.read(buffer)) != -1; total += count) {
                out.write(buffer, 0, count);
            }
            return total;
        } catch (StreamDecryptionException e) {
            throw new DecryptionException(e.failure());
        }
    }

    public static List<String> recipients(InputStream in) throws IOException, DecryptionException {
        return RecipientHeader.read(in).stanzas().stream().map(stanza -> Fingerprint.format(stanza.fingerprint())).toList();
    }

    public long changeRecipients(InputStream in, OutputStream out, X25519KeyPair me, List<byte[]> add, List<String> remove)
            throws IOException, DecryptionException {
        RecipientHeader header = RecipientHeader.read(in);
        byte[] fileKey = unlock(header, me);
        try {
            Map<String, RecipientStanza> kept = new LinkedHashMap<>();
            header.stanzas().forEach(stanza -> kept.put(Fingerprint.format(stanza.fingerprint()), stanza));
            for (String fingerprint : remove) {
                if (kept.remove(fingerprint) == null) {
                    throw new IllegalArgumentException(fingerprint + " is not a recipient of this file");
                }
            }
            unique(add).forEach((fingerprint, key) -> kept.putIfAbsent(fingerprint, wrap(fileKey, key)));
            if (kept.isEmpty()) {
                throw new IllegalArgumentException("A file needs at least one recipient");
            }
            RecipientHeader updated = new RecipientHeader(new ArrayList<>(kept.values()), header.payloadNonce(), new byte[RecipientHeader.MAC_LENGTH]);
            out.write(sign(updated, fileKey).encode());
            return in.transferTo(out);
        } finally {
            Secrets.wipe(fileKey);
        }
    }

    public long rekey(InputStream in, OutputStream out, X25519KeyPair me, List<byte[]> recipientPublicKeys) throws IOException, DecryptionException {
        try {
            return encrypt(open(in, me), out, recipientPublicKeys);
        } catch (StreamDecryptionException e) {
            throw new DecryptionException(e.failure());
        }
    }

    private RecipientStanza wrap(byte[] fileKey, byte[] recipientPublicKey) {
        byte[] fingerprint = Fingerprint.bytes(recipientPublicKey);
        Encapsulation encapsulation = DhkemX25519.encap(recipientPublicKey, random);
        byte[] wrapped = Hpke.keySchedule(HpkeMode.BASE, encapsulation.sharedSecret(), FILE_KEY_INFO).seal(fingerprint, fileKey);
        return new RecipientStanza(fingerprint, encapsulation.enc(), wrapped);
    }

    private static byte[] unlock(RecipientHeader header, X25519KeyPair me) throws DecryptionException {
        byte[] mine = Fingerprint.bytes(me.publicKey());
        boolean listed = false;
        for (RecipientStanza stanza : header.stanzas()) {
            if (!stanza.isFor(mine)) {
                continue;
            }
            listed = true;
            try {
                byte[] sharedSecret = DhkemX25519.decap(stanza.enc(), me);
                byte[] fileKey = Hpke.keySchedule(HpkeMode.BASE, sharedSecret, FILE_KEY_INFO).open(mine, stanza.wrappedFileKey());
                if (MessageDigest.isEqual(headerMac(header, fileKey), header.mac())) {
                    return fileKey;
                }
                Secrets.wipe(fileKey);
                throw new DecryptionException(DecryptionFailure.AUTHENTICATION_FAILED);
            } catch (AEADBadTagException | IllegalArgumentException e) {
                continue;
            }
        }
        throw new DecryptionException(listed ? DecryptionFailure.AUTHENTICATION_FAILED : DecryptionFailure.NOT_A_RECIPIENT);
    }

    private static RecipientHeader sign(RecipientHeader header, byte[] fileKey) {
        return header.withMac(headerMac(header, fileKey));
    }

    private static byte[] headerMac(RecipientHeader header, byte[] fileKey) {
        byte[] macKey = Hkdf.expand(Hkdf.extract(new byte[0], fileKey), HEADER_MAC_INFO, Hkdf.HASH_LENGTH);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            return mac.doFinal(header.authenticatedPart());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        } finally {
            Secrets.wipe(macKey);
        }
    }

    private static Map<String, byte[]> unique(List<byte[]> publicKeys) {
        Map<String, byte[]> keys = new LinkedHashMap<>();
        for (byte[] key : publicKeys) {
            if (key.length != X25519KeyPair.KEY_LENGTH) {
                throw new IllegalArgumentException("Recipient keys are 32-byte X25519 public keys");
            }
            keys.putIfAbsent(Fingerprint.of(key), key.clone());
        }
        if (keys.isEmpty() && !publicKeys.isEmpty()) {
            throw new IllegalArgumentException("No recipients");
        }
        return keys;
    }
}
