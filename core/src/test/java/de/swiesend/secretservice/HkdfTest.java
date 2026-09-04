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

    @Test
    void rfc5869TestCase2LongInputs() {
        // A.2: inputs longer than one hash block, exercising multi-block expand. Folded in from
        // the hardened module's HkdfKatTest, which duplicated this suite against the same class.
        byte[] ikm = hex("000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f");
        byte[] salt = hex("606162636465666768696a6b6c6d6e6f"
                + "707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f"
                + "909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        byte[] info = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] expected = hex("b11e398dc80327a1c8e7f78c596a4934"
                + "4f012eda2d4efad8a050cc4c19afa97c"
                + "59045a99cac7827271cb41c65e590e09"
                + "da3275600c2f09b8367793a9aca3db71"
                + "cc30c58179ec3e87c14c01d5c1f3434f"
                + "1d87");
        assertArrayEquals(expected, Hkdf.extractThenExpandSha256(salt, ikm, info, 82));
    }

    @Test
    void nullSaltEqualsHashLenZeros() {
        // RFC 5869 defines an absent salt as HashLen zero bytes; the at.favre library this class
        // replaced behaved the same, and both the KEM combine and the transport session key rely
        // on it.
        byte[] ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] info = hex("f0f1f2f3");
        assertArrayEquals(
                Hkdf.extractThenExpandSha256(new byte[32], ikm, info, 32),
                Hkdf.extractThenExpandSha256(null, ikm, info, 32),
                "null salt must derive identically to an explicit 32-byte zero salt");
    }
}
