package de.swiesend.secretservice;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * RFC 5869 test vectors for the HKDF that every transport-encrypted session key passes through.
 *
 * <p>The implementation replaced the {@code at.favre.lib} dependency with the JDK's native
 * {@code javax.crypto.KDF}; equivalence was verified by hand at the time, but nothing in CI
 * re-checked it. These are the official vectors, byte for byte.</p>
 */
class HkdfTest {

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @Test
    void rfc5869TestCase1SaltAndInfo() {
        // A.1: SHA-256, with salt and info -- the fully-parameterised path.
        byte[] okm = Hkdf.extractThenExpandSha256(
                hex("000102030405060708090a0b0c"),
                hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                hex("f0f1f2f3f4f5f6f7f8f9"),
                42);
        assertArrayEquals(hex("3cb25f25faacd57a90434f64d0362f2a"
                + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865"), okm);
    }

    @Test
    void rfc5869TestCase3NoSaltNoInfo() {
        // A.3: SHA-256, salt and info both absent -- the exact shape TransportEncryption uses for
        // the session key, so this is the vector that guards the wire.
        byte[] okm = Hkdf.extractThenExpandSha256(
                null,
                hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                null,
                42);
        assertArrayEquals(hex("8da4e775a563c18f715f802a063c5a31"
                + "b8a11f5c5ee1879ec3454e5f3c738d2d"
                + "9d201395faa4b61a96c8"), okm);
    }

    @Test
    void sixteenByteOutputMatchesTheSessionKeyLength() {
        // TransportEncryption asks for 16 bytes (AES-128). A truncated HKDF output is defined as
        // the prefix of the full output, so this is TC3's first 16 bytes.
        byte[] okm = Hkdf.extractThenExpandSha256(
                null,
                hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                null,
                16);
        assertArrayEquals(hex("8da4e775a563c18f715f802a063c5a31"), okm);
    }
}
