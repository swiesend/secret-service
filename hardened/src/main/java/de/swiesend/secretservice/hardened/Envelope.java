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
 * magic(4="SSv1") | version(1) | flags(1) | kem_id(1) |
 * salt_len(1)    | salt[16]    |
 * epoch_len(1)   | epoch_id[n] |
 * nonce(12)      | aead_ct[...] | tag(16 included in aead_ct by GCM)
 * </pre>
 *
 * <p>The envelope is stored as the raw secret body; transport encryption then
 * wraps it.</p>
 *
 * <h3>Algorithm agility via {@code kem_id}</h3>
 * <p>The {@code kem_id} byte declares which KEM the envelope was sealed under.
 * It is the forward-compatible hook that lets new post-quantum components
 * (HQC-192, triple hybrid, future NIST additions) land without a format
 * migration. Readers reject unknown values; writers set the id to match the
 * configured {@link HybridKem}. See {@link #KEM_ID_NONE},
 * {@link #KEM_ID_X25519_MLKEM768}, {@link #KEM_ID_X25519_HQC192} (reserved),
 * and {@link #KEM_ID_X25519_MLKEM768_HQC192} (reserved).</p>
 *
 * <p>The redundant {@link #FLAG_PQ_HYBRID} bit is preserved for quick inspection
 * but {@code kem_id} is authoritative.</p>
 */
public final class Envelope {

    public static final byte[] MAGIC = new byte[]{'S', 'S', 'v', '1'};
    public static final byte VERSION_1 = 0x01;
    public static final int NONCE_LEN = 12;
    public static final int SALT_LEN = 16;

    public static final byte FLAG_PQ_HYBRID = 0x01;
    public static final byte FLAG_LIVE_TOTP = 0x02;
    public static final byte FLAG_STORED_STEP_TOTP = 0x04;

    /** Classical X25519 only; no PQ component. */
    public static final byte KEM_ID_NONE = 0x00;
    /** X25519 combined with ML-KEM-768 (FIPS 203). Today's recommended PQ default. */
    public static final byte KEM_ID_X25519_MLKEM768 = 0x01;
    /** Reserved: X25519 combined with HQC-192 (NIST Round 4 selection, March 2025). Not yet implemented. */
    public static final byte KEM_ID_X25519_HQC192 = 0x02;
    /** Reserved: triple hybrid X25519 + ML-KEM-768 + HQC-192 for long-term archival. Not yet implemented. */
    public static final byte KEM_ID_X25519_MLKEM768_HQC192 = 0x03;

    private final byte version;
    private final byte flags;
    private final byte kemId;
    private final byte[] salt;
    private final byte[] epochId;
    private final byte[] nonce;
    private final byte[] aeadCiphertext;

    public Envelope(byte version, byte flags, byte kemId, byte[] salt, byte[] epochId, byte[] nonce, byte[] aeadCiphertext) {
        this.version = version;
        this.flags = flags;
        this.kemId = kemId;
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
    public byte kemId()   { return kemId; }
    public byte[] salt()           { return salt.clone(); }
    public byte[] epochId()        { return epochId.clone(); }
    public byte[] nonce()          { return nonce.clone(); }
    public byte[] aeadCiphertext() { return aeadCiphertext.clone(); }

    public boolean hasFlag(byte flag) { return (flags & flag) == flag; }

    public byte[] toBytes() {
        int total = MAGIC.length
                + 1 // version
                + 1 // flags
                + 1 // kem_id
                + 1 + salt.length
                + 1 + epochId.length
                + nonce.length
                + aeadCiphertext.length;
        ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        buf.put(MAGIC);
        buf.put(version);
        buf.put(flags);
        buf.put(kemId);
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
        if (input.length < MAGIC.length + 3 + 1 + SALT_LEN + 1 + 1 + NONCE_LEN) {
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
        byte kemId = buf.get();
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

            return new Envelope(version, flags, kemId, salt, epochId, nonce, ct);
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

    /** Human-readable label for a {@code kem_id}, suitable for attributes / logs. */
    public static String kemIdLabel(byte kemId) {
        return switch (kemId) {
            case KEM_ID_NONE -> "x25519";
            case KEM_ID_X25519_MLKEM768 -> "x25519+ml-kem-768";
            case KEM_ID_X25519_HQC192 -> "x25519+hqc-192";
            case KEM_ID_X25519_MLKEM768_HQC192 -> "x25519+ml-kem-768+hqc-192";
            default -> "kem-id-0x" + Integer.toHexString(kemId & 0xff);
        };
    }
}
