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
 * kem_ct_len(2)  | kem_ct[m]   |  // KEM ciphertext (m=0 when kem_id=KEM_ID_NONE)
 * nonce(12)      | aead_ct[...]   // tag(16) included in aead_ct by GCM
 * </pre>
 *
 * <p>The envelope is stored as the raw secret body; transport encryption then
 * wraps it.</p>
 *
 * <p>The {@code kem_ct} field carries the public part of a KEM encapsulation
 * (e.g. ephemeral X25519 SPKI followed by ML-KEM ciphertext when
 * {@link #KEM_ID_X25519_MLKEM768}). The reader pairs it with the matching epoch
 * private key (held by the EpochKeystore) to recover the shared secret that
 * participates in HKDF DEK derivation. {@code kem_ct_len = 0} means the
 * envelope used no KEM and the DEK was derived from pepper + TOTP + salt only.</p>
 *
 * <h3>Algorithm agility via {@code kem_id}</h3>
 * <p>The {@code kem_id} byte declares which KEM the envelope was sealed under.
 * It is the forward-compatible hook that lets a new post-quantum component
 * (for example, HQC-192) land without a format migration. Readers fall back to
 * a generic {@code "kem-id-0xNN"} label for unknown ids; writers stamp the id
 * reported by the configured {@link HybridKem}. Today's shipped values are
 * {@link #KEM_ID_NONE} and {@link #KEM_ID_X25519_MLKEM768};
 * {@link #KEM_ID_X25519_HQC192} is reserved for the NIST Round 4 HQC
 * alternative. Exotic combinations such as triple hybrid are not shipped and
 * not recommended -- consumers who genuinely need them can allocate a new id
 * value without a format change.</p>
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

    /** No KEM at all: the DEK is derived from pepper + TOTP + salt only. Legacy alpha envelopes. */
    public static final byte KEM_ID_NONE = 0x00;
    /** X25519 combined with ML-KEM-768 (FIPS 203). Today's recommended PQ default. */
    public static final byte KEM_ID_X25519_MLKEM768 = 0x01;
    /** Reserved: X25519 combined with HQC-192 (NIST Round 4 selection, March 2025). Not yet implemented. */
    public static final byte KEM_ID_X25519_HQC192 = 0x02;
    /** Classical X25519-only KEM; no PQ component. Epoch-ratcheted for forward secrecy. */
    public static final byte KEM_ID_X25519 = 0x03;

    private final byte version;
    private final byte flags;
    private final byte kemId;
    private final byte[] salt;
    private final byte[] epochId;
    private final byte[] kemCiphertext;
    private final byte[] nonce;
    private final byte[] aeadCiphertext;

    public Envelope(byte version, byte flags, byte kemId, byte[] salt, byte[] epochId,
                    byte[] kemCiphertext, byte[] nonce, byte[] aeadCiphertext) {
        this.version = version;
        this.flags = flags;
        this.kemId = kemId;
        this.salt = Objects.requireNonNull(salt, "salt");
        this.epochId = Objects.requireNonNull(epochId, "epochId");
        this.kemCiphertext = Objects.requireNonNull(kemCiphertext, "kemCiphertext");
        this.nonce = Objects.requireNonNull(nonce, "nonce");
        this.aeadCiphertext = Objects.requireNonNull(aeadCiphertext, "aeadCiphertext");
        if (salt.length != SALT_LEN) throw new IllegalArgumentException("salt must be " + SALT_LEN + " bytes");
        if (nonce.length != NONCE_LEN) throw new IllegalArgumentException("nonce must be " + NONCE_LEN + " bytes");
        if (epochId.length > 255) throw new IllegalArgumentException("epochId too long (max 255)");
        if (epochId.length == 0) throw new IllegalArgumentException("epochId must not be empty");
        if (kemCiphertext.length > 0xFFFF) {
            throw new IllegalArgumentException("kemCiphertext too long (max 65535)");
        }
        if ((kemId == KEM_ID_NONE) != (kemCiphertext.length == 0)) {
            throw new IllegalArgumentException(
                    "kemCiphertext length must be 0 iff kem_id == KEM_ID_NONE; got kem_id=0x"
                            + Integer.toHexString(kemId & 0xff) + ", kemCiphertext.len=" + kemCiphertext.length);
        }
        if (aeadCiphertext.length == 0) throw new IllegalArgumentException("aeadCiphertext must not be empty");
    }

    public byte version() { return version; }
    public byte flags()   { return flags; }
    public byte kemId()   { return kemId; }
    public byte[] salt()           { return salt.clone(); }
    public byte[] epochId()        { return epochId.clone(); }
    public byte[] kemCiphertext()  { return kemCiphertext.clone(); }
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
                + 2 + kemCiphertext.length
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
        buf.putShort((short) kemCiphertext.length);
        buf.put(kemCiphertext);
        buf.put(nonce);
        buf.put(aeadCiphertext);
        return buf.array();
    }

    public static Envelope fromBytes(byte[] input) {
        Objects.requireNonNull(input, "input");
        // minimum: magic + version + flags + kem_id + salt_len + salt + epoch_len + 1 +
        //          kem_ct_len(2) + nonce + aead_ct(>=16)
        if (input.length < MAGIC.length + 1 + 1 + 1 + 1 + SALT_LEN + 1 + 1 + 2 + NONCE_LEN + 16) {
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

            int kemCtLen = Short.toUnsignedInt(buf.getShort());
            if (kemCtLen > buf.remaining() - NONCE_LEN - 16) {
                throw new IllegalArgumentException("kem_ct_len overruns envelope: " + kemCtLen);
            }
            byte[] kemCt = new byte[kemCtLen];
            buf.get(kemCt);

            byte[] nonce = new byte[NONCE_LEN];
            buf.get(nonce);

            int ctLen = buf.remaining();
            // AES-GCM ciphertext always includes a 16-byte tag; reject anything shorter.
            if (ctLen < 16) throw new IllegalArgumentException("aead ciphertext too short: " + ctLen);
            byte[] ct = new byte[ctLen];
            buf.get(ct);

            return new Envelope(version, flags, kemId, salt, epochId, kemCt, nonce, ct);
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

    /**
     * Human-readable label for a {@code kem_id}, suitable for attributes / logs. Delegates to
     * {@link KemId#labelFor(byte)} so the id-to-label mapping lives in exactly one place.
     */
    public static String kemIdLabel(byte kemId) {
        return KemId.labelFor(kemId);
    }
}
