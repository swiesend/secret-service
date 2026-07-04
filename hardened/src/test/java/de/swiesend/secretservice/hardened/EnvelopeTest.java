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

    private static final byte[] EMPTY = new byte[0];

    /** A minimal valid v2 envelope (no KEM, no TOTP) for the poke/validation tests. */
    private static Envelope simple() {
        return new Envelope(Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), "item-1".getBytes(),
                Envelope.TOTP_MODE_NONE, 0L, EMPTY, bytes(12, 2), bytes(32, 3));
    }

    @Test
    void roundTripPreservesAllFields_withKemCt() {
        byte[] salt = bytes(Envelope.SALT_LEN, 0x11);
        byte[] epoch = "epoch-abc".getBytes();
        byte[] itemId = "item-42".getBytes();
        byte[] kemCt = bytes(1090, 0x44);   // size of a real ML-KEM ciphertext + X25519 spki
        byte[] nonce = bytes(Envelope.NONCE_LEN, 0x22);
        byte[] ct = bytes(64, 0x33);
        Envelope original = new Envelope(Envelope.VERSION_2,
                (byte) (Envelope.FLAG_PQ_HYBRID | Envelope.FLAG_STORED_STEP_TOTP),
                Envelope.KEM_ID_X25519_MLKEM768,
                salt, epoch, itemId, Envelope.TOTP_MODE_STORED_STEP, 123456789L, kemCt, nonce, ct);

        Envelope parsed = Envelope.fromBytes(original.toBytes());

        assertEquals(Envelope.VERSION_2, parsed.version());
        assertTrue(parsed.hasFlag(Envelope.FLAG_PQ_HYBRID));
        assertTrue(parsed.hasFlag(Envelope.FLAG_STORED_STEP_TOTP));
        assertFalse(parsed.hasFlag(Envelope.FLAG_LIVE_TOTP));
        assertEquals(Envelope.KEM_ID_X25519_MLKEM768, parsed.kemId());
        assertArrayEquals(salt, parsed.salt());
        assertArrayEquals(epoch, parsed.epochId());
        assertArrayEquals(itemId, parsed.itemId());
        assertEquals(Envelope.TOTP_MODE_STORED_STEP, parsed.totpMode());
        assertEquals(123456789L, parsed.totpStep());
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
        Envelope original = new Envelope(Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                salt, epoch, "id".getBytes(), Envelope.TOTP_MODE_NONE, 0L, EMPTY, nonce, ct);
        Envelope parsed = Envelope.fromBytes(original.toBytes());
        assertEquals(Envelope.KEM_ID_NONE, parsed.kemId());
        assertArrayEquals(EMPTY, parsed.kemCiphertext());
        assertArrayEquals(ct, parsed.aeadCiphertext());
    }

    @Test
    void associatedDataIsTheHeaderPrefixOfToBytes() {
        Envelope e = simple();
        byte[] full = e.toBytes();
        byte[] aad = e.associatedData();
        assertTrue(aad.length < full.length, "AAD is the header, shorter than the whole envelope");
        assertArrayEquals(Arrays.copyOf(full, aad.length), aad,
                "associatedData() must equal the header prefix of toBytes()");
        // The trailing bytes are exactly the AEAD ciphertext.
        assertArrayEquals(e.aeadCiphertext(), Arrays.copyOfRange(full, aad.length, full.length));
    }

    @Test
    void kemIdAndKemCtMustBeConsistent() {
        // kem_id == NONE but kem_ct non-empty -- reject
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), "i".getBytes(), Envelope.TOTP_MODE_NONE, 0L,
                bytes(8, 9), bytes(12, 2), bytes(32, 3)));
        // kem_id != NONE but kem_ct empty -- reject
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_X25519_MLKEM768,
                bytes(16, 1), "e".getBytes(), "i".getBytes(), Envelope.TOTP_MODE_NONE, 0L,
                EMPTY, bytes(12, 2), bytes(32, 3)));
    }

    @Test
    void kemIdRoundTripsAllReservedValues() {
        byte[] salt = bytes(Envelope.SALT_LEN, 0x11);
        byte[] epoch = "e".getBytes();
        byte[] id = "i".getBytes();
        byte[] nonce = bytes(Envelope.NONCE_LEN, 0x22);
        byte[] ct = bytes(32, 0x33);
        byte[] kemCtForPq = bytes(64, 0x55);
        Envelope none = new Envelope(Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                salt, epoch, id, Envelope.TOTP_MODE_NONE, 0L, EMPTY, nonce, ct);
        assertEquals(Envelope.KEM_ID_NONE, Envelope.fromBytes(none.toBytes()).kemId());
        for (byte kid : new byte[]{
                Envelope.KEM_ID_X25519,
                Envelope.KEM_ID_X25519_MLKEM768,
                Envelope.KEM_ID_X25519_HQC192,
                (byte) 0x7f}) {  // arbitrary unknown id -- agility check
            Envelope env = new Envelope(Envelope.VERSION_2, (byte) 0, kid, salt, epoch, id,
                    Envelope.TOTP_MODE_NONE, 0L, kemCtForPq, nonce, ct);
            assertEquals(kid, Envelope.fromBytes(env.toBytes()).kemId());
        }
    }

    @Test
    void kemIdLabelIsSensible() {
        assertEquals("none", Envelope.kemIdLabel(Envelope.KEM_ID_NONE));
        assertEquals("x25519", Envelope.kemIdLabel(Envelope.KEM_ID_X25519));
        assertEquals("x25519+ml-kem-768", Envelope.kemIdLabel(Envelope.KEM_ID_X25519_MLKEM768));
        assertEquals("x25519+hqc-192", Envelope.kemIdLabel(Envelope.KEM_ID_X25519_HQC192));
        assertTrue(Envelope.kemIdLabel((byte) 0x7f).startsWith("kem-id-0x"));
    }

    @Test
    void magicIsRequired() {
        byte[] env = simple().toBytes();
        env[0] = 'X';
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void rejectsUnsupportedVersion() {
        byte[] env = simple().toBytes();
        env[4] = 99;
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void rejectsLegacyV1WithReadableMessage() {
        byte[] env = simple().toBytes();
        env[4] = Envelope.VERSION_1; // pretend it is an old v1 envelope
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Envelope.fromBytes(env));
        assertTrue(e.getMessage().contains("v1"),
                "v1 rejection message should name the legacy format; was: " + e.getMessage());
    }

    @Test
    void rejectsInvalidTotpMode() {
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), "i".getBytes(), (byte) 0x7f, 0L,
                EMPTY, bytes(12, 2), bytes(32, 3)));
    }

    @Test
    void rejectsTruncatedInput() {
        byte[] env = simple().toBytes();
        byte[] truncated = Arrays.copyOf(env, 10);
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(truncated));
    }

    @Test
    void rejectsTooShortAeadCiphertext() {
        byte[] env = simple().toBytes();
        byte[] truncated = Arrays.copyOf(env, env.length - 20);
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(truncated));
    }

    @Test
    void rejectsInvalidSaltLengthField() {
        byte[] env = simple().toBytes();
        env[7] = 8; // fake salt_len = 8 (real is 16); salt_len is still at offset 7 in v2
        assertThrows(IllegalArgumentException.class, () -> Envelope.fromBytes(env));
    }

    @Test
    void looksLikeEnvelopeRejectsShortAndForeign() {
        assertFalse(Envelope.looksLikeEnvelope(null));
        assertFalse(Envelope.looksLikeEnvelope(new byte[]{'S', 'S'}));
        assertFalse(Envelope.looksLikeEnvelope("plain secret".getBytes()));
        assertTrue(Envelope.looksLikeEnvelope(simple().toBytes()));
    }

    @Test
    void constructorValidatesLengths() {
        // bad salt len
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(15, 1), "e".getBytes(), "i".getBytes(), Envelope.TOTP_MODE_NONE, 0L,
                EMPTY, bytes(12, 2), bytes(32, 3)));
        // bad nonce len
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), "i".getBytes(), Envelope.TOTP_MODE_NONE, 0L,
                EMPTY, bytes(11, 2), bytes(32, 3)));
        // empty epoch
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), new byte[0], "i".getBytes(), Envelope.TOTP_MODE_NONE, 0L,
                EMPTY, bytes(12, 2), bytes(32, 3)));
        // empty item id
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), new byte[0], Envelope.TOTP_MODE_NONE, 0L,
                EMPTY, bytes(12, 2), bytes(32, 3)));
        // empty aead ct
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_2, (byte) 0, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), "i".getBytes(), Envelope.TOTP_MODE_NONE, 0L,
                EMPTY, bytes(12, 2), new byte[0]));
    }
}
