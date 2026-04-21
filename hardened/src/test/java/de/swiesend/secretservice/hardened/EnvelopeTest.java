package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnvelopeTest {

    private static byte[] bytes(int n, int fill) {
        byte[] a = new byte[n];
        Arrays.fill(a, (byte) fill);
        return a;
    }

    @Test
    void roundTripPreservesAllFields() {
        byte[] salt = bytes(Envelope.SALT_LEN, 0x11);
        byte[] epoch = "epoch-abc".getBytes();
        byte[] nonce = bytes(Envelope.NONCE_LEN, 0x22);
        byte[] ct = bytes(64, 0x33);
        Envelope original = new Envelope(Envelope.VERSION_1,
                (byte) (Envelope.FLAG_PQ_HYBRID | Envelope.FLAG_STORED_STEP_TOTP),
                Envelope.KEM_ID_X25519_MLKEM768,
                salt, epoch, nonce, ct);

        Envelope parsed = Envelope.fromBytes(original.toBytes());

        assertEquals(Envelope.VERSION_1, parsed.version());
        assertTrue(parsed.hasFlag(Envelope.FLAG_PQ_HYBRID));
        assertTrue(parsed.hasFlag(Envelope.FLAG_STORED_STEP_TOTP));
        assertFalse(parsed.hasFlag(Envelope.FLAG_LIVE_TOTP));
        assertEquals(Envelope.KEM_ID_X25519_MLKEM768, parsed.kemId());
        assertArrayEquals(salt, parsed.salt());
        assertArrayEquals(epoch, parsed.epochId());
        assertArrayEquals(nonce, parsed.nonce());
        assertArrayEquals(ct, parsed.aeadCiphertext());
    }

    @Test
    void kemIdRoundTripsAllReservedValues() {
        byte[] salt = bytes(Envelope.SALT_LEN, 0x11);
        byte[] epoch = "e".getBytes();
        byte[] nonce = bytes(Envelope.NONCE_LEN, 0x22);
        byte[] ct = bytes(32, 0x33);
        for (byte id : new byte[]{
                Envelope.KEM_ID_NONE,
                Envelope.KEM_ID_X25519_MLKEM768,
                Envelope.KEM_ID_X25519_HQC192,
                (byte) 0x7f}) {  // arbitrary unknown id -- agility check
            Envelope env = new Envelope(Envelope.VERSION_1, (byte) 0, id, salt, epoch, nonce, ct);
            assertEquals(id, Envelope.fromBytes(env.toBytes()).kemId());
        }
    }

    @Test
    void kemIdLabelIsSensible() {
        assertEquals("x25519", Envelope.kemIdLabel(Envelope.KEM_ID_NONE));
        assertEquals("x25519+ml-kem-768", Envelope.kemIdLabel(Envelope.KEM_ID_X25519_MLKEM768));
        assertEquals("x25519+hqc-192", Envelope.kemIdLabel(Envelope.KEM_ID_X25519_HQC192));
        // Unknown ids fall through to a generic label so future (opt-in, consumer-allocated)
        // combinations round-trip without a format bump.
        assertTrue(Envelope.kemIdLabel((byte) 0x7f).startsWith("kem-id-0x"));
    }

    @Test
    void magicIsRequired() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(12, 2), bytes(32, 3)).toBytes();
        env[0] = 'X';
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void rejectsUnsupportedVersion() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(12, 2), bytes(32, 3)).toBytes();
        env[4] = 99; // version byte
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void rejectsTruncatedInput() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(12, 2), bytes(32, 3)).toBytes();
        byte[] truncated = Arrays.copyOf(env, 10);
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(truncated));
    }

    @Test
    void rejectsTooShortAeadCiphertext() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(12, 2), bytes(32, 3)).toBytes();
        byte[] truncated = Arrays.copyOf(env, env.length - 20);
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(truncated));
    }

    @Test
    void rejectsInvalidSaltLengthField() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(12, 2), bytes(32, 3)).toBytes();
        // With kem_id inserted, salt_len now lives at offset 7 (magic[4] + version + flags + kem_id).
        env[7] = 8; // fake salt_len = 8
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void looksLikeEnvelopeRejectsShortAndForeign() {
        assertFalse(Envelope.looksLikeEnvelope(null));
        assertFalse(Envelope.looksLikeEnvelope(new byte[]{'S', 'S'}));
        assertFalse(Envelope.looksLikeEnvelope("plain secret".getBytes()));
        byte[] good = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(12, 2), bytes(32, 3)).toBytes();
        assertTrue(Envelope.looksLikeEnvelope(good));
    }

    @Test
    void constructorValidatesLengths() {
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(15, 1), "e".getBytes(), bytes(12, 2), bytes(32, 3)));
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(11, 2), bytes(32, 3)));
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), new byte[0], bytes(12, 2), bytes(32, 3)));
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(12, 2), new byte[0]));
    }
}
