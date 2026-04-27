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

    private static byte[] EMPTY = new byte[0];

    @Test
    void roundTripPreservesAllFields_withKemCt() {
        byte[] salt = bytes(Envelope.SALT_LEN, 0x11);
        byte[] epoch = "epoch-abc".getBytes();
        byte[] kemCt = bytes(1090, 0x44);   // size of a real ML-KEM ciphertext + X25519 spki
        byte[] nonce = bytes(Envelope.NONCE_LEN, 0x22);
        byte[] ct = bytes(64, 0x33);
        Envelope original = new Envelope(Envelope.VERSION_1,
                (byte) (Envelope.FLAG_PQ_HYBRID | Envelope.FLAG_STORED_STEP_TOTP),
                Envelope.KEM_ID_X25519_MLKEM768,
                salt, epoch, kemCt, nonce, ct);

        Envelope parsed = Envelope.fromBytes(original.toBytes());

        assertEquals(Envelope.VERSION_1, parsed.version());
        assertTrue(parsed.hasFlag(Envelope.FLAG_PQ_HYBRID));
        assertTrue(parsed.hasFlag(Envelope.FLAG_STORED_STEP_TOTP));
        assertFalse(parsed.hasFlag(Envelope.FLAG_LIVE_TOTP));
        assertEquals(Envelope.KEM_ID_X25519_MLKEM768, parsed.kemId());
        assertArrayEquals(salt, parsed.salt());
        assertArrayEquals(epoch, parsed.epochId());
        assertArrayEquals(kemCt, parsed.kemCiphertext());
        assertArrayEquals(nonce, parsed.nonce());
        assertArrayEquals(ct, parsed.aeadCiphertext());
    }

    @Test
    void roundTripPreservesAllFields_classicalNoKemCt() {
        byte[] salt = bytes(Envelope.SALT_LEN, 0x11);
        byte[] epoch = "epoch-classical".getBytes();
        byte[] nonce = bytes(Envelope.NONCE_LEN, 0x22);
        byte[] ct = bytes(48, 0x33);
        Envelope original = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                salt, epoch, EMPTY, nonce, ct);
        Envelope parsed = Envelope.fromBytes(original.toBytes());
        assertEquals(Envelope.KEM_ID_NONE, parsed.kemId());
        assertArrayEquals(EMPTY, parsed.kemCiphertext());
        assertArrayEquals(ct, parsed.aeadCiphertext());
    }

    @Test
    void kemIdAndKemCtMustBeConsistent() {
        // kem_id == NONE but kem_ct non-empty -- reject
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), bytes(8, 9), bytes(12, 2), bytes(32, 3)));
        // kem_id != NONE but kem_ct empty -- reject
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_X25519_MLKEM768,
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3)));
    }

    @Test
    void kemIdRoundTripsAllReservedValues() {
        byte[] salt = bytes(Envelope.SALT_LEN, 0x11);
        byte[] epoch = "e".getBytes();
        byte[] nonce = bytes(Envelope.NONCE_LEN, 0x22);
        byte[] ct = bytes(32, 0x33);
        // With kem_id != NONE, kem_ct must be non-empty (any size is fine for the round-trip).
        byte[] kemCtForPq = bytes(64, 0x55);
        Envelope none = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                salt, epoch, EMPTY, nonce, ct);
        assertEquals(Envelope.KEM_ID_NONE, Envelope.fromBytes(none.toBytes()).kemId());
        for (byte id : new byte[]{
                Envelope.KEM_ID_X25519_MLKEM768,
                Envelope.KEM_ID_X25519_HQC192,
                (byte) 0x7f}) {  // arbitrary unknown id -- agility check
            Envelope env = new Envelope(Envelope.VERSION_1, (byte) 0, id, salt, epoch, kemCtForPq, nonce, ct);
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
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3)).toBytes();
        env[0] = 'X';
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void rejectsUnsupportedVersion() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3)).toBytes();
        env[4] = 99;
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void rejectsTruncatedInput() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3)).toBytes();
        byte[] truncated = Arrays.copyOf(env, 10);
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(truncated));
    }

    @Test
    void rejectsTooShortAeadCiphertext() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3)).toBytes();
        byte[] truncated = Arrays.copyOf(env, env.length - 20);
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(truncated));
    }

    @Test
    void rejectsInvalidSaltLengthField() {
        byte[] env = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3)).toBytes();
        env[7] = 8; // fake salt_len = 8 (real is 16)
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void looksLikeEnvelopeRejectsShortAndForeign() {
        assertFalse(Envelope.looksLikeEnvelope(null));
        assertFalse(Envelope.looksLikeEnvelope(new byte[]{'S', 'S'}));
        assertFalse(Envelope.looksLikeEnvelope("plain secret".getBytes()));
        byte[] good = new Envelope(Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3)).toBytes();
        assertTrue(Envelope.looksLikeEnvelope(good));
    }

    @Test
    void constructorValidatesLengths() {
        // bad salt len
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(15, 1), "e".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3)));
        // bad nonce len
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(11, 2), bytes(32, 3)));
        // empty epoch
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), new byte[0], EMPTY, bytes(12, 2), bytes(32, 3)));
        // empty aead ct
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_1, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), EMPTY, bytes(12, 2), new byte[0]));
    }
}
