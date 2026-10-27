package com.danyastry.encryption.core.acl;

import com.danyastry.encryption.core.error.DecryptionException;
import com.danyastry.encryption.core.error.DecryptionFailure;
import com.danyastry.encryption.core.hpke.X25519KeyPair;
import com.danyastry.encryption.core.password.PasswordEnvelope;
import com.danyastry.encryption.core.stream.StreamChunks;
import com.danyastry.encryption.core.util.Fingerprint;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public record RecipientHeader(List<RecipientStanza> stanzas, byte[] payloadNonce, byte[] mac) {

    public static final int TYPE_RECIPIENT_STREAM = 0x05;
    public static final int MAX_RECIPIENTS = 64;
    public static final int MAC_LENGTH = 32;

    public RecipientHeader {
        if (stanzas.isEmpty() || stanzas.size() > MAX_RECIPIENTS) {
            throw new IllegalArgumentException("A file needs 1.." + MAX_RECIPIENTS + " recipients, got " + stanzas.size());
        }
        if (payloadNonce.length != StreamChunks.PAYLOAD_NONCE_LENGTH || mac.length != MAC_LENGTH) {
            throw new IllegalArgumentException("Payload nonce or MAC has the wrong length");
        }
        stanzas = List.copyOf(stanzas);
        payloadNonce = payloadNonce.clone();
        mac = mac.clone();
    }

    public byte[] authenticatedPart() {
        ByteBuffer buffer = ByteBuffer.allocate(PasswordEnvelope.MAGIC.length + 3 + stanzas.size() * RecipientStanza.LENGTH + payloadNonce.length)
                .put(PasswordEnvelope.MAGIC)
                .put((byte) PasswordEnvelope.VERSION)
                .put((byte) TYPE_RECIPIENT_STREAM)
                .put((byte) stanzas.size());
        for (RecipientStanza stanza : stanzas) {
            buffer.put(stanza.fingerprint()).put(stanza.enc()).put(stanza.wrappedFileKey());
        }
        return buffer.put(payloadNonce).array();
    }

    public byte[] encode() {
        byte[] authenticated = authenticatedPart();
        byte[] out = Arrays.copyOf(authenticated, authenticated.length + MAC_LENGTH);
        System.arraycopy(mac, 0, out, authenticated.length, MAC_LENGTH);
        return out;
    }

    public RecipientHeader withMac(byte[] newMac) {
        return new RecipientHeader(stanzas, payloadNonce, newMac);
    }

    public static RecipientHeader read(InputStream in) throws DecryptionException, IOException {
        DataInputStream data = new DataInputStream(in);
        try {
            byte[] magic = new byte[PasswordEnvelope.MAGIC.length];
            data.readFully(magic);
            if (!Arrays.equals(magic, PasswordEnvelope.MAGIC)) {
                throw new DecryptionException(DecryptionFailure.NOT_AN_ENVELOPE);
            }
            if (data.readUnsignedByte() != PasswordEnvelope.VERSION) {
                throw new DecryptionException(DecryptionFailure.UNSUPPORTED_VERSION);
            }
            if (data.readUnsignedByte() != TYPE_RECIPIENT_STREAM) {
                throw new DecryptionException(DecryptionFailure.WRONG_TYPE);
            }
            int count = data.readUnsignedByte();
            if (count == 0 || count > MAX_RECIPIENTS) {
                throw new DecryptionException(DecryptionFailure.MALFORMED);
            }
            List<RecipientStanza> stanzas = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                byte[] fingerprint = new byte[Fingerprint.LENGTH];
                byte[] enc = new byte[X25519KeyPair.KEY_LENGTH];
                byte[] wrapped = new byte[RecipientStanza.WRAPPED_KEY_LENGTH];
                data.readFully(fingerprint);
                data.readFully(enc);
                data.readFully(wrapped);
                stanzas.add(new RecipientStanza(fingerprint, enc, wrapped));
            }
            byte[] nonce = new byte[StreamChunks.PAYLOAD_NONCE_LENGTH];
            byte[] mac = new byte[MAC_LENGTH];
            data.readFully(nonce);
            data.readFully(mac);
            return new RecipientHeader(stanzas, nonce, mac);
        } catch (EOFException e) {
            throw new DecryptionException(DecryptionFailure.MALFORMED);
        }
    }

    @Override
    public byte[] payloadNonce() {
        return payloadNonce.clone();
    }

    @Override
    public byte[] mac() {
        return mac.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof RecipientHeader header && stanzas.equals(header.stanzas) && Arrays.equals(payloadNonce, header.payloadNonce)
                && Arrays.equals(mac, header.mac);
    }

    @Override
    public int hashCode() {
        return stanzas.hashCode();
    }

    @Override
    public String toString() {
        return "RecipientHeader[" + stanzas.size() + " recipients]";
    }
}
