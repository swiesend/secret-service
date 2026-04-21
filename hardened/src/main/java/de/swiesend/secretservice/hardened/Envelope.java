package de.swiesend.secretservice.hardened;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/**
 * Versioned binary envelope for hardened secret-service items.
 *
 * <pre>
 * magic(4="SSv1") | version(1) | flags(1) |
 * salt_len(1)    | salt[16]    |
 * epoch_len(1)   | epoch_id[n] |
 * nonce(12)      | aead_ct[...] | tag(16 included in aead_ct by GCM)
 * </pre>
 *
 * The envelope is stored as the raw secret body; transport encryption then wraps it.
 */
public final class Envelope {

    public static final byte[] MAGIC = new byte[]{'S', 'S', 'v', '1'};
    public static final byte VERSION_1 = 0x01;
    public static final int NONCE_LEN = 12;
    public static final int SALT_LEN = 16;

    public static final byte FLAG_PQ_HYBRID = 0x01;
    public static final byte FLAG_LIVE_TOTP = 0x02;
    public static final byte FLAG_STORED_STEP_TOTP = 0x04;

    private final byte version;
    private final byte flags;
    private final byte[] salt;
    private final byte[] epochId;
    private final byte[] nonce;
    private final byte[] aeadCiphertext;

    public Envelope(byte version, byte flags, byte[] salt, byte[] epochId, byte[] nonce, byte[] aeadCiphertext) {
        this.version = version;
        this.flags = flags;
        this.salt = Objects.requireNonNull(salt, "salt");
        this.epochId = Objects.requireNonNull(epochId, "epochId");
        this.nonce = Objects.requireNonNull(nonce, "nonce");
        this.aeadCiphertext = Objects.requireNonNull(aeadCiphertext, "aeadCiphertext");
        if (salt.length != SALT_LEN) throw new IllegalArgumentException("salt must be " + SALT_LEN + " bytes");
        if (nonce.length != NONCE_LEN) throw new IllegalArgumentException("nonce must be " + NONCE_LEN + " bytes");
        if (epochId.length > 255) throw new IllegalArgumentException("epochId too long (max 255)");
        if (epochId.length == 0) throw new IllegalArgumentException("epochId must not be empty");
        if (aeadCiphertext.length == 0) throw new IllegalArgumentException("aeadCiphertext must not be empty");
    }

    public byte version() { return version; }
    public byte flags()   { return flags; }
    public byte[] salt()           { return salt.clone(); }
    public byte[] epochId()        { return epochId.clone(); }
    public byte[] nonce()          { return nonce.clone(); }
    public byte[] aeadCiphertext() { return aeadCiphertext.clone(); }

    public boolean hasFlag(byte flag) { return (flags & flag) == flag; }

    public byte[] toBytes() {
        int total = MAGIC.length
                + 1 // version
                + 1 // flags
                + 1 + salt.length
                + 1 + epochId.length
                + nonce.length
                + aeadCiphertext.length;
        ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        buf.put(MAGIC);
        buf.put(version);
        buf.put(flags);
        buf.put((byte) salt.length);
        buf.put(salt);
        buf.put((byte) epochId.length);
        buf.put(epochId);
        buf.put(nonce);
        buf.put(aeadCiphertext);
        return buf.array();
    }

    public static Envelope fromBytes(byte[] input) {
        Objects.requireNonNull(input, "input");
        if (input.length < MAGIC.length + 2 + 1 + SALT_LEN + 1 + 1 + NONCE_LEN) {
            throw new IllegalArgumentException("envelope too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[MAGIC.length];
        buf.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IllegalArgumentException("bad magic");
        }
        byte version = buf.get();
        if (version != VERSION_1) {
            throw new IllegalArgumentException("unsupported envelope version: " + version);
        }
        byte flags = buf.get();
        try {
            int saltLen = Byte.toUnsignedInt(buf.get());
            if (saltLen != SALT_LEN) throw new IllegalArgumentException("bad salt length: " + saltLen);
            byte[] salt = new byte[saltLen];
            buf.get(salt);

            int epochLen = Byte.toUnsignedInt(buf.get());
            if (epochLen == 0) throw new IllegalArgumentException("empty epoch id");
            byte[] epochId = new byte[epochLen];
            buf.get(epochId);

            byte[] nonce = new byte[NONCE_LEN];
            buf.get(nonce);

            int ctLen = buf.remaining();
            // AES-GCM ciphertext always includes a 16-byte tag; reject anything shorter.
            if (ctLen < 16) throw new IllegalArgumentException("aead ciphertext too short: " + ctLen);
            byte[] ct = new byte[ctLen];
            buf.get(ct);

            return new Envelope(version, flags, salt, epochId, nonce, ct);
        } catch (BufferUnderflowException e) {
            throw new IllegalArgumentException("truncated envelope", e);
        }
    }

    public static boolean looksLikeEnvelope(byte[] input) {
        if (input == null || input.length < MAGIC.length) return false;
        for (int i = 0; i < MAGIC.length; i++) {
            if (input[i] != MAGIC[i]) return false;
        }
        return true;
    }
}
