package de.swiesend.secretservice.hardened;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/**
 * Versioned binary envelope for hardened secret-service items (format v3).
 *
 * <pre>
 * magic(4="SSv1") | version(1) | flags(1) |
 * aead_id(1)      | kdf_id(1)   | kem_id(1) |   // cipher-suite selectors
 * salt_len(1)     | salt[16]    |
 * epoch_len(1)    | epoch_id[n] |
 * item_id_len(1)  | item_id[k]  |               // authenticated item identity
 * kem_ct_len(2)   | kem_ct[m]   |               // KEM ciphertext (m=0 when kem_id=KEM_ID_NONE)
 * nonce(12)       | aead_ct[...]                // tag(16) included in aead_ct by the AEAD
 * </pre>
 *
 * <p>The entire header (everything preceding {@code aead_ct}) is fed to the AEAD as associated data
 * via {@link #associatedData()}, so a tampered version/flags/suite-selector/item-id or a relocated
 * ciphertext fails authentication rather than being silently trusted.</p>
 *
 * <h3>Crypto agility via {@code aead_id} / {@code kdf_id} / {@code kem_id}</h3>
 * <p>Each primitive is named by a wire byte, so a new AEAD, KDF, or KEM lands without a format
 * migration. Today's values: {@code aead_id} {@link #AEAD_ID_AES256_GCM} / {@link #AEAD_ID_CHACHA20_POLY1305};
 * {@code kdf_id} {@link #KDF_ID_HKDF_SHA256}; {@code kem_id} {@link #KEM_ID_X25519} /
 * {@link #KEM_ID_X25519_MLKEM768}. Unknown ids round-trip through the parser (so future ciphertexts
 * are inspectable); the reader rejects an id it cannot execute at decrypt time. The redundant
 * {@link #FLAG_PQ_HYBRID} bit is preserved for quick inspection but {@code kem_id} is authoritative.</p>
 *
 * <h3>Version 3 only — the frozen wire format</h3>
 * <p>{@link #fromBytes(byte[])} accepts only {@link #VERSION_3}. The earlier alpha {@code VERSION_1}
 * (unauthenticated attributes) and {@code VERSION_2} (TOTP fields, no suite selectors) formats are
 * rejected; they were never released, so there is nothing to migrate.</p>
 *
 * <p><b>Stability policy:</b> v3 is the <em>frozen</em> wire format for the release line. The exact
 * byte layout is pinned by a committed regression fixture ({@code EnvelopeTest.v3WireFormatFixture*}),
 * so an accidental change fails a test. A genuine format change must allocate a new {@code version}
 * byte, keep v3 readable (or provide a re-wrap migration), and add a fresh fixture -- never mutate v3
 * in place. New algorithms do <em>not</em> need a version bump: allocate a new {@code aead_id} /
 * {@code kdf_id} / {@code kem_id} instead.</p>
 */
public final class Envelope {

    public static final byte[] MAGIC = new byte[]{'S', 'S', 'v', '1'};
    /** Legacy alpha format (item-id/TOTP in mutable attributes, narrow AAD). Rejected on read. */
    public static final byte VERSION_1 = 0x01;
    /** Superseded alpha format (authenticated item-id + TOTP mode/step, no suite selectors). Rejected on read. */
    public static final byte VERSION_2 = 0x02;
    /** Current format: suite-selector bytes, authenticated item-id, no TOTP. */
    public static final byte VERSION_3 = 0x03;
    public static final int NONCE_LEN = 12;
    public static final int SALT_LEN = 16;

    public static final byte FLAG_PQ_HYBRID = 0x01;

    /** AEAD selectors. Both use a 12-byte nonce, a 16-byte tag, and a 32-byte key. */
    public static final byte AEAD_ID_AES256_GCM = 0x01;
    public static final byte AEAD_ID_CHACHA20_POLY1305 = 0x02;

    /** KDF selectors. */
    public static final byte KDF_ID_HKDF_SHA256 = 0x01;

    /** No KEM at all: the DEK is derived from pepper only. Legacy; never written since the KEM is always on. */
    public static final byte KEM_ID_NONE = 0x00;
    /** X25519 combined with ML-KEM-768 (FIPS 203). Today's recommended PQ default. */
    public static final byte KEM_ID_X25519_MLKEM768 = 0x01;
    /** Reserved: X25519 combined with HQC-192 (NIST Round 4 selection, March 2025). Not yet implemented. */
    public static final byte KEM_ID_X25519_HQC192 = 0x02;
    /** Classical X25519-only KEM; no PQ component. Epoch-ratcheted for forward secrecy. */
    public static final byte KEM_ID_X25519 = 0x03;

    private final byte version;
    private final byte flags;
    private final byte aeadId;
    private final byte kdfId;
    private final byte kemId;
    private final byte[] salt;
    private final byte[] epochId;
    private final byte[] itemId;
    private final byte[] kemCiphertext;
    private final byte[] nonce;
    private final byte[] aeadCiphertext;

    public Envelope(byte version, byte flags, byte aeadId, byte kdfId, byte kemId,
                    byte[] salt, byte[] epochId, byte[] itemId,
                    byte[] kemCiphertext, byte[] nonce, byte[] aeadCiphertext) {
        this.version = version;
        this.flags = flags;
        this.aeadId = aeadId;
        this.kdfId = kdfId;
        this.kemId = kemId;
        this.salt = Objects.requireNonNull(salt, "salt");
        this.epochId = Objects.requireNonNull(epochId, "epochId");
        this.itemId = Objects.requireNonNull(itemId, "itemId");
        this.kemCiphertext = Objects.requireNonNull(kemCiphertext, "kemCiphertext");
        this.nonce = Objects.requireNonNull(nonce, "nonce");
        this.aeadCiphertext = Objects.requireNonNull(aeadCiphertext, "aeadCiphertext");
        if (salt.length != SALT_LEN) throw new IllegalArgumentException("salt must be " + SALT_LEN + " bytes");
        if (nonce.length != NONCE_LEN) throw new IllegalArgumentException("nonce must be " + NONCE_LEN + " bytes");
        if (epochId.length > 255) throw new IllegalArgumentException("epochId too long (max 255)");
        if (epochId.length == 0) throw new IllegalArgumentException("epochId must not be empty");
        if (itemId.length > 255) throw new IllegalArgumentException("itemId too long (max 255)");
        if (itemId.length == 0) throw new IllegalArgumentException("itemId must not be empty");
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
    public byte aeadId()  { return aeadId; }
    public byte kdfId()   { return kdfId; }
    public byte kemId()   { return kemId; }
    public byte[] salt()           { return salt.clone(); }
    public byte[] epochId()        { return epochId.clone(); }
    public byte[] itemId()         { return itemId.clone(); }
    public byte[] kemCiphertext()  { return kemCiphertext.clone(); }
    public byte[] nonce()          { return nonce.clone(); }
    public byte[] aeadCiphertext() { return aeadCiphertext.clone(); }

    public boolean hasFlag(byte flag) { return (flags & flag) == flag; }

    /** Serialised header length for the given field sizes (everything up to {@code aead_ct}). */
    private static int headerLength(int epochLen, int itemLen, int kemCtLen) {
        return MAGIC.length
                + 1 // version
                + 1 // flags
                + 1 // aead_id
                + 1 // kdf_id
                + 1 // kem_id
                + 1 + SALT_LEN
                + 1 + epochLen
                + 1 + itemLen
                + 2 + kemCtLen
                + NONCE_LEN;
    }

    private static void putHeader(ByteBuffer buf, byte version, byte flags, byte aeadId, byte kdfId, byte kemId,
                                  byte[] salt, byte[] epochId, byte[] itemId, byte[] kemCiphertext, byte[] nonce) {
        buf.put(MAGIC);
        buf.put(version);
        buf.put(flags);
        buf.put(aeadId);
        buf.put(kdfId);
        buf.put(kemId);
        buf.put((byte) salt.length);
        buf.put(salt);
        buf.put((byte) epochId.length);
        buf.put(epochId);
        buf.put((byte) itemId.length);
        buf.put(itemId);
        buf.putShort((short) kemCiphertext.length);
        buf.put(kemCiphertext);
        buf.put(nonce);
    }

    /**
     * The full header (magic through nonce) that the AEAD authenticates as associated data, built
     * directly from field values. Callers use this at <em>encrypt</em> time (before the ciphertext
     * exists); {@link #associatedData()} returns the same bytes for a parsed envelope.
     */
    public static byte[] associatedData(byte version, byte flags, byte aeadId, byte kdfId, byte kemId,
                                        byte[] salt, byte[] epochId, byte[] itemId, byte[] kemCiphertext, byte[] nonce) {
        ByteBuffer buf = ByteBuffer.allocate(headerLength(epochId.length, itemId.length, kemCiphertext.length))
                .order(ByteOrder.BIG_ENDIAN);
        putHeader(buf, version, flags, aeadId, kdfId, kemId, salt, epochId, itemId, kemCiphertext, nonce);
        return buf.array();
    }

    /** Associated data for this parsed envelope. */
    public byte[] associatedData() {
        return associatedData(version, flags, aeadId, kdfId, kemId, salt, epochId, itemId, kemCiphertext, nonce);
    }

    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(
                headerLength(epochId.length, itemId.length, kemCiphertext.length) + aeadCiphertext.length)
                .order(ByteOrder.BIG_ENDIAN);
        putHeader(buf, version, flags, aeadId, kdfId, kemId, salt, epochId, itemId, kemCiphertext, nonce);
        buf.put(aeadCiphertext);
        return buf.array();
    }

    public static Envelope fromBytes(byte[] input) {
        Objects.requireNonNull(input, "input");
        // minimum: magic + version + flags + aead_id + kdf_id + kem_id + salt_len + salt +
        //          epoch_len + 1 + item_id_len + 1 + kem_ct_len(2) + nonce + aead_ct(>=16)
        int min = MAGIC.length + 1 + 1 + 1 + 1 + 1 + 1 + SALT_LEN + 1 + 1 + 1 + 1 + 2 + NONCE_LEN + 16;
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
        if (version == VERSION_1 || version == VERSION_2) {
            throw new IllegalArgumentException(
                    "legacy v" + version + " envelope (pre-suite-selector format) is no longer supported; "
                            + "re-write the item under the current hardened format");
        }
        if (version != VERSION_3) {
            throw new IllegalArgumentException("unsupported envelope version: " + version);
        }
        byte flags = buf.get();
        byte aeadId = buf.get();
        byte kdfId = buf.get();
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

            int kemCtLen = Short.toUnsignedInt(buf.getShort());
            if (kemCtLen > buf.remaining() - NONCE_LEN - 16) {
                throw new IllegalArgumentException("kem_ct_len overruns envelope: " + kemCtLen);
            }
            byte[] kemCt = new byte[kemCtLen];
            buf.get(kemCt);

            byte[] nonce = new byte[NONCE_LEN];
            buf.get(nonce);

            int ctLen = buf.remaining();
            // Every shipped AEAD (GCM, ChaCha20-Poly1305) appends a 16-byte tag; reject anything shorter.
            if (ctLen < 16) throw new IllegalArgumentException("aead ciphertext too short: " + ctLen);
            byte[] ct = new byte[ctLen];
            buf.get(ct);

            return new Envelope(version, flags, aeadId, kdfId, kemId, salt, epochId, itemId, kemCt, nonce, ct);
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
