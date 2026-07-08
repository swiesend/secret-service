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

    /** A minimal valid v3 envelope (no KEM) for the poke/validation tests. */
    private static Envelope simple() {
        return new Envelope(Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM,
                Envelope.KDF_ID_HKDF_SHA256, Envelope.KEM_ID_NONE,
                bytes(16, 1), "e".getBytes(), "item-1".getBytes(), EMPTY, bytes(12, 2), bytes(32, 3));
    }

    @Test
    void roundTripPreservesAllFields_withKemCt() {
        byte[] salt = bytes(Envelope.SALT_LEN, 0x11);
        byte[] epoch = "epoch-abc".getBytes();
        byte[] itemId = "item-42".getBytes();
        byte[] kemCt = bytes(1090, 0x44);   // size of a real ML-KEM ciphertext + X25519 spki
        byte[] nonce = bytes(Envelope.NONCE_LEN, 0x22);
        byte[] ct = bytes(64, 0x33);
        Envelope original = new Envelope(Envelope.VERSION_3, Envelope.FLAG_PQ_HYBRID,
                Envelope.AEAD_ID_CHACHA20_POLY1305, Envelope.KDF_ID_HKDF_SHA256,
                Envelope.KEM_ID_X25519_MLKEM768, salt, epoch, itemId, kemCt, nonce, ct);

        Envelope parsed = Envelope.fromBytes(original.toBytes());

        assertEquals(Envelope.VERSION_3, parsed.version());
        assertTrue(parsed.hasFlag(Envelope.FLAG_PQ_HYBRID));
        assertEquals(Envelope.AEAD_ID_CHACHA20_POLY1305, parsed.aeadId());
        assertEquals(Envelope.KDF_ID_HKDF_SHA256, parsed.kdfId());
        assertEquals(Envelope.KEM_ID_X25519_MLKEM768, parsed.kemId());
        assertArrayEquals(salt, parsed.salt());
        assertArrayEquals(epoch, parsed.epochId());
        assertArrayEquals(itemId, parsed.itemId());
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
        Envelope original = new Envelope(Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM,
                Envelope.KDF_ID_HKDF_SHA256, Envelope.KEM_ID_NONE,
                salt, epoch, "id".getBytes(), EMPTY, nonce, ct);
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
        assertArrayEquals(e.aeadCiphertext(), Arrays.copyOfRange(full, aad.length, full.length));
    }

    @Test
    void suiteSelectorBytesRoundTripUnknownValues() {
        // aead_id and kdf_id round-trip arbitrary (future/unknown) values without a format change,
        // mirroring kem_id agility. Rejection of an unsupported suite happens at decrypt time.
        Envelope e = new Envelope(Envelope.VERSION_3, (byte) 0, (byte) 0x7e, (byte) 0x7f,
                Envelope.KEM_ID_X25519, bytes(16, 1), "e".getBytes(), "i".getBytes(),
                bytes(48, 9), bytes(12, 2), bytes(32, 3));
        Envelope parsed = Envelope.fromBytes(e.toBytes());
        assertEquals((byte) 0x7e, parsed.aeadId());
        assertEquals((byte) 0x7f, parsed.kdfId());
    }

    @Test
    void kemIdAndKemCtMustBeConsistent() {
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM, Envelope.KDF_ID_HKDF_SHA256,
                Envelope.KEM_ID_NONE, bytes(16, 1), "e".getBytes(), "i".getBytes(),
                bytes(8, 9), bytes(12, 2), bytes(32, 3)));
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM, Envelope.KDF_ID_HKDF_SHA256,
                Envelope.KEM_ID_X25519_MLKEM768, bytes(16, 1), "e".getBytes(), "i".getBytes(),
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
        Envelope none = new Envelope(Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM,
                Envelope.KDF_ID_HKDF_SHA256, Envelope.KEM_ID_NONE, salt, epoch, id, EMPTY, nonce, ct);
        assertEquals(Envelope.KEM_ID_NONE, Envelope.fromBytes(none.toBytes()).kemId());
        for (byte kid : new byte[]{
                Envelope.KEM_ID_X25519,
                Envelope.KEM_ID_X25519_MLKEM768,
                Envelope.KEM_ID_X25519_HQC192,
                (byte) 0x7f}) {
            Envelope env = new Envelope(Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM,
                    Envelope.KDF_ID_HKDF_SHA256, kid, salt, epoch, id, kemCtForPq, nonce, ct);
            assertEquals(kid, Envelope.fromBytes(env.toBytes()).kemId());
        }
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
    void rejectsLegacyV1AndV2WithReadableMessage() {
        for (byte legacy : new byte[]{Envelope.VERSION_1, Envelope.VERSION_2}) {
            byte[] env = simple().toBytes();
            env[4] = legacy;
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> Envelope.fromBytes(env));
            assertTrue(e.getMessage().contains("legacy"),
                    "v" + legacy + " rejection should name the legacy format; was: " + e.getMessage());
        }
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
        // magic(4)+version(1)+flags(1)+aead_id(1)+kdf_id(1)+kem_id(1) = salt_len at offset 9
        env[9] = 8;
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
                Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM, Envelope.KDF_ID_HKDF_SHA256,
                Envelope.KEM_ID_NONE, bytes(15, 1), "e".getBytes(), "i".getBytes(),
                EMPTY, bytes(12, 2), bytes(32, 3)));
        // bad nonce len
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM, Envelope.KDF_ID_HKDF_SHA256,
                Envelope.KEM_ID_NONE, bytes(16, 1), "e".getBytes(), "i".getBytes(),
                EMPTY, bytes(11, 2), bytes(32, 3)));
        // empty epoch
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM, Envelope.KDF_ID_HKDF_SHA256,
                Envelope.KEM_ID_NONE, bytes(16, 1), new byte[0], "i".getBytes(),
                EMPTY, bytes(12, 2), bytes(32, 3)));
        // empty item id
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM, Envelope.KDF_ID_HKDF_SHA256,
                Envelope.KEM_ID_NONE, bytes(16, 1), "e".getBytes(), new byte[0],
                EMPTY, bytes(12, 2), bytes(32, 3)));
        // empty aead ct
        assertThrows(IllegalArgumentException.class, () -> new Envelope(
                Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM, Envelope.KDF_ID_HKDF_SHA256,
                Envelope.KEM_ID_NONE, bytes(16, 1), "e".getBytes(), "i".getBytes(),
                EMPTY, bytes(12, 2), new byte[0]));
    }
}
