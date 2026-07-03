package de.swiesend.secretservice.hardened;

import java.util.Optional;

/**
 * Typed view of the {@link Envelope} {@code kem_id} wire byte. Centralizing the id, its
 * human-readable label, and whether it carries a post-quantum ciphertext half in one table
 * removes the scattered {@code == KEM_ID_*} comparisons that previously let the label and the
 * hybrid decision drift apart (the "NONE labelled x25519" bug). Callers that make decisions on
 * the kem should branch on this enum, not on the raw byte.
 *
 * <p>The wire byte remains a {@code byte} on {@link Envelope} for forward compatibility: unknown
 * ids round-trip and {@link #labelFor(byte)} renders them generically, so a future consumer can
 * allocate a new id without a format change.</p>
 */
public enum KemId {

    /** No KEM: DEK from pepper + TOTP + salt only. Only appears on legacy alpha envelopes. */
    NONE(Envelope.KEM_ID_NONE, "none", false),
    /** Classical X25519-only KEM, epoch-ratcheted for forward secrecy. */
    X25519(Envelope.KEM_ID_X25519, "x25519", false),
    /** X25519 + ML-KEM-768 (FIPS 203) hybrid. */
    X25519_MLKEM768(Envelope.KEM_ID_X25519_MLKEM768, "x25519+ml-kem-768", true),
    /** Reserved: X25519 + HQC-192 (NIST Round 4). Not yet implemented. */
    X25519_HQC192(Envelope.KEM_ID_X25519_HQC192, "x25519+hqc-192", true);

    private final byte id;
    private final String label;
    private final boolean carriesPqCiphertext;

    KemId(byte id, String label, boolean carriesPqCiphertext) {
        this.id = id;
        this.label = label;
        this.carriesPqCiphertext = carriesPqCiphertext;
    }

    /** The wire byte stamped into {@code Envelope.kem_id}. */
    public byte id() { return id; }

    /** Human-readable label for attributes and logs. */
    public String label() { return label; }

    /**
     * True iff envelopes sealed under this id include an ML-KEM (post-quantum) ciphertext half.
     * Drives both the {@link Envelope#FLAG_PQ_HYBRID} write flag and the {@code envelopeIsHybrid}
     * read decision, so the two can never disagree.
     */
    public boolean carriesPqCiphertext() { return carriesPqCiphertext; }

    /** Resolve a known kem from its wire byte, or empty for an unknown (agility) id. */
    public static Optional<KemId> fromId(byte id) {
        for (KemId k : values()) {
            if (k.id == id) return Optional.of(k);
        }
        return Optional.empty();
    }

    /** Label for any id byte, falling back to a generic {@code kem-id-0xNN} for unknown ids. */
    public static String labelFor(byte id) {
        return fromId(id).map(KemId::label).orElse("kem-id-0x" + Integer.toHexString(id & 0xff));
    }
}
