package de.swiesend.secretservice.hardened;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/**
 * Versioned binary envelope for hardened secret-service items (format v2).
 *
 * <pre>
 * magic(4="SSv1") | version(1) | flags(1) | kem_id(1) |
 * salt_len(1)     | salt[16]    |
 * epoch_len(1)    | epoch_id[n] |
 * item_id_len(1)  | item_id[k]  |   // authenticated item identity (was a mutable D-Bus attribute)
 * totp_mode(1)    |                 // 0=NO_TOTP, 1=STORED_STEP, 2=LIVE_CODE
 * totp_step(8)    |                 // big-endian; 0 unless STORED_STEP
 * kem_ct_len(2)   | kem_ct[m]   |   // KEM ciphertext (m=0 when kem_id=KEM_ID_NONE)
 * nonce(12)       | aead_ct[...]    // tag(16) included in aead_ct by GCM
 * </pre>
 *
 * <p>The entire header (everything preceding {@code aead_ct}) is fed to AES-GCM as associated
 * data via {@link #associatedData()}, so a tampered version/flags/kem_id/item_id/totp field or a
 * relocated ciphertext fails authentication rather than being silently trusted. Item identity and
 * the TOTP mode/step used to live only in mutable D-Bus attributes; they are now inside the
 * authenticated envelope and read from here, not from attributes.</p>
 *
 * <h3>Version 2 only</h3>
 * <p>{@link #fromBytes(byte[])} accepts only {@link #VERSION_2}. The alpha {@code VERSION_1} format
 * (no authenticated item-id/TOTP fields, narrower AAD) is rejected with a clear message. There is
 * no persisted-format compatibility guarantee across alpha revisions.</p>
 *
 * <h3>Algorithm agility via {@code kem_id}</h3>
 * <p>The {@code kem_id} byte declares which KEM the envelope was sealed under. It is the
 * forward-compatible hook that lets a new post-quantum component land without a format migration.
 * Readers fall back to a generic {@code "kem-id-0xNN"} label for unknown ids; writers stamp the id
 * reported by the configured {@link HybridKem}. The redundant {@link #FLAG_PQ_HYBRID} bit is
 * preserved for quick inspection but {@code kem_id} is authoritative.</p>
 */
public final class Envelope {

    public static final byte[] MAGIC = new byte[]{'S', 'S', 'v', '1'};
    /** Legacy alpha format (item-id/TOTP in mutable attributes, narrow AAD). Rejected on read. */
    public static final byte VERSION_1 = 0x01;
    /** Current format: authenticated item-id + TOTP mode/step, full-header AAD. */
    public static final byte VERSION_2 = 0x02;
    public static final int NONCE_LEN = 12;
    public static final int SALT_LEN = 16;

    public static final byte FLAG_PQ_HYBRID = 0x01;
    public static final byte FLAG_LIVE_TOTP = 0x02;
    public static final byte FLAG_STORED_STEP_TOTP = 0x04;

    /** Authenticated TOTP-mode wire codes carried in the {@code totp_mode} byte. */
    public static final byte TOTP_MODE_NONE = 0x00;
    public static final byte TOTP_MODE_STORED_STEP = 0x01;
    public static final byte TOTP_MODE_LIVE_CODE = 0x02;

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
    private final byte[] itemId;
    private final byte totpMode;
    private final long totpStep;
    private final byte[] kemCiphertext;
    private final byte[] nonce;
    private final byte[] aeadCiphertext;

    public Envelope(byte version, byte flags, byte kemId, byte[] salt, byte[] epochId,
                    byte[] itemId, byte totpMode, long totpStep,
                    byte[] kemCiphertext, byte[] nonce, byte[] aeadCiphertext) {
        this.version = version;
        this.flags = flags;
        this.kemId = kemId;
        this.salt = Objects.requireNonNull(salt, "salt");
        this.epochId = Objects.requireNonNull(epochId, "epochId");
        this.itemId = Objects.requireNonNull(itemId, "itemId");
        this.totpMode = totpMode;
        this.totpStep = totpStep;
        this.kemCiphertext = Objects.requireNonNull(kemCiphertext, "kemCiphertext");
        this.nonce = Objects.requireNonNull(nonce, "nonce");
        this.aeadCiphertext = Objects.requireNonNull(aeadCiphertext, "aeadCiphertext");
        if (salt.length != SALT_LEN) throw new IllegalArgumentException("salt must be " + SALT_LEN + " bytes");
        if (nonce.length != NONCE_LEN) throw new IllegalArgumentException("nonce must be " + NONCE_LEN + " bytes");
        if (epochId.length > 255) throw new IllegalArgumentException("epochId too long (max 255)");
        if (epochId.length == 0) throw new IllegalArgumentException("epochId must not be empty");
        if (itemId.length > 255) throw new IllegalArgumentException("itemId too long (max 255)");
        if (itemId.length == 0) throw new IllegalArgumentException("itemId must not be empty");
        if (totpMode != TOTP_MODE_NONE && totpMode != TOTP_MODE_STORED_STEP && totpMode != TOTP_MODE_LIVE_CODE) {
            throw new IllegalArgumentException("invalid totp_mode: 0x" + Integer.toHexString(totpMode & 0xff));
        }
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
    public byte[] itemId()         { return itemId.clone(); }
    public byte totpMode()         { return totpMode; }
    public long totpStep()         { return totpStep; }
    public byte[] kemCiphertext()  { return kemCiphertext.clone(); }
    public byte[] nonce()          { return nonce.clone(); }
    public byte[] aeadCiphertext() { return aeadCiphertext.clone(); }

    public boolean hasFlag(byte flag) { return (flags & flag) == flag; }

    /** Serialised header length for the given field sizes (everything up to {@code aead_ct}). */
    private static int headerLength(int epochLen, int itemLen, int kemCtLen) {
        return MAGIC.length
                + 1 // version
                + 1 // flags
                + 1 // kem_id
                + 1 + SALT_LEN
                + 1 + epochLen
                + 1 + itemLen
                + 1 // totp_mode
                + 8 // totp_step
                + 2 + kemCtLen
                + NONCE_LEN;
    }

    private static void putHeader(ByteBuffer buf, byte version, byte flags, byte kemId, byte[] salt,
                                  byte[] epochId, byte[] itemId, byte totpMode, long totpStep,
                                  byte[] kemCiphertext, byte[] nonce) {
        buf.put(MAGIC);
        buf.put(version);
        buf.put(flags);
        buf.put(kemId);
        buf.put((byte) salt.length);
        buf.put(salt);
        buf.put((byte) epochId.length);
        buf.put(epochId);
        buf.put((byte) itemId.length);
        buf.put(itemId);
        buf.put(totpMode);
        buf.putLong(totpStep);
        buf.putShort((short) kemCiphertext.length);
        buf.put(kemCiphertext);
        buf.put(nonce);
    }

    /**
     * The full header (magic through nonce) that AES-GCM authenticates as associated data, built
     * directly from field values. Callers use this at <em>encrypt</em> time (before the ciphertext
     * exists); {@link #associatedData()} returns the same bytes for a parsed envelope. Any change to
     * version, flags, kem_id, salt, epoch, item-id, TOTP mode/step, KEM ciphertext, or nonce
     * therefore breaks decryption instead of being silently accepted.
     */
    public static byte[] associatedData(byte version, byte flags, byte kemId, byte[] salt, byte[] epochId,
                                        byte[] itemId, byte totpMode, long totpStep,
                                        byte[] kemCiphertext, byte[] nonce) {
        ByteBuffer buf = ByteBuffer.allocate(headerLength(epochId.length, itemId.length, kemCiphertext.length))
                .order(ByteOrder.BIG_ENDIAN);
        putHeader(buf, version, flags, kemId, salt, epochId, itemId, totpMode, totpStep, kemCiphertext, nonce);
        return buf.array();
    }

    /** Associated data for this parsed envelope; see the static {@link #associatedData(byte, byte, byte, byte[], byte[], byte[], byte, long, byte[], byte[])}. */
    public byte[] associatedData() {
        return associatedData(version, flags, kemId, salt, epochId, itemId, totpMode, totpStep,
                kemCiphertext, nonce);
    }

    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(
                headerLength(epochId.length, itemId.length, kemCiphertext.length) + aeadCiphertext.length)
                .order(ByteOrder.BIG_ENDIAN);
        putHeader(buf, version, flags, kemId, salt, epochId, itemId, totpMode, totpStep, kemCiphertext, nonce);
        buf.put(aeadCiphertext);
        return buf.array();
    }

    public static Envelope fromBytes(byte[] input) {
        Objects.requireNonNull(input, "input");
        // minimum: magic + version + flags + kem_id + salt_len + salt + epoch_len + 1 +
        //          item_id_len + 1 + totp_mode + totp_step(8) + kem_ct_len(2) + nonce + aead_ct(>=16)
        int min = MAGIC.length + 1 + 1 + 1 + 1 + SALT_LEN + 1 + 1 + 1 + 1 + 1 + 8 + 2 + NONCE_LEN + 16;
        if (input.length < min) {
            throw new IllegalArgumentException("envelope too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[MAGIC.length];
        buf.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IllegalArgumentException("bad magic");
        }
        byte version = buf.get();
        if (version == VERSION_1) {
            throw new IllegalArgumentException(
                    "legacy v1 envelope (unauthenticated item-id/TOTP, narrow AAD) is no longer "
                            + "supported; re-write the item under the current hardened format");
        }
        if (version != VERSION_2) {
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

            int itemLen = Byte.toUnsignedInt(buf.get());
            if (itemLen == 0) throw new IllegalArgumentException("empty item id");
            byte[] itemId = new byte[itemLen];
            buf.get(itemId);

            byte totpMode = buf.get();
            long totpStep = buf.getLong();

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

            return new Envelope(version, flags, kemId, salt, epochId, itemId, totpMode, totpStep,
                    kemCt, nonce, ct);
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
