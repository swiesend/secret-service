package de.swiesend.secretservice.hardened;

/**
 * Selectable AEAD cipher for hardened item envelopes, chosen when a collection is built.
 * Both suites are JDK-native and use a 32-byte key,
 * a 12-byte nonce, and a 16-byte tag; the choice is recorded in the authenticated {@code aead_id}
 * envelope byte, so items written under either cipher remain readable.
 */
public enum AeadId {
    /** AES-256-GCM (default). */
    AES_256_GCM(Envelope.AEAD_ID_AES256_GCM),
    /** ChaCha20-Poly1305 (RFC 8439). */
    CHACHA20_POLY1305(Envelope.AEAD_ID_CHACHA20_POLY1305);

    private final byte id;

    AeadId(byte id) { this.id = id; }

    /** The wire byte stamped into the envelope's {@code aead_id} field. */
    public byte id() { return id; }
}
