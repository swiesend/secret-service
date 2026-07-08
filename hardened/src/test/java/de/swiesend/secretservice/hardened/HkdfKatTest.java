package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.Hkdf;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * RFC 5869 known-answer tests for {@link Hkdf} (HKDF-SHA256). These pin the derivation to the
 * standard vectors, proving the native {@code javax.crypto.KDF} implementation is byte-correct and
 * therefore interchangeable with the former {@code at.favre.lib:hkdf} dependency it replaced.
 */
class HkdfKatTest {

    private static final HexFormat HEX = HexFormat.of();

    private static byte[] h(String hex) { return HEX.parseHex(hex); }

    /** RFC 5869 Appendix A, Test Case 1 (basic, SHA-256). */
    @Test
    void rfc5869TestCase1() {
        byte[] ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = h("000102030405060708090a0b0c");
        byte[] info = h("f0f1f2f3f4f5f6f7f8f9");
        byte[] expected = h("3cb25f25faacd57a90434f64d0362f2a"
                + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865");
        assertArrayEquals(expected, Hkdf.extractThenExpandSha256(salt, ikm, info, 42));
    }

    /** RFC 5869 Appendix A, Test Case 2 (longer inputs/output, SHA-256). */
    @Test
    void rfc5869TestCase2() {
        byte[] ikm = h("000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f"
                + "303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f");
        byte[] salt = h("606162636465666768696a6b6c6d6e6f"
                + "707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f"
                + "909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        byte[] info = h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] expected = h("b11e398dc80327a1c8e7f78c596a4934"
                + "4f012eda2d4efad8a050cc4c19afa97c"
                + "59045a99cac7827271cb41c65e590e09"
                + "da3275600c2f09b8367793a9aca3db71"
                + "cc30c58179ec3e87c14c01d5c1f3434f"
                + "1d87");
        assertArrayEquals(expected, Hkdf.extractThenExpandSha256(salt, ikm, info, 82));
    }

    /**
     * A {@code null} salt must be the RFC 5869 "absent salt" (HashLen zero bytes), matching the
     * former at.favre behavior used by the always-on KEM combine and the transport session key.
     */
    @Test
    void nullSaltEqualsHashLenZeros() {
        byte[] ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] info = h("f0f1f2f3");
        assertArrayEquals(
                Hkdf.extractThenExpandSha256(new byte[32], ikm, info, 32),
                Hkdf.extractThenExpandSha256(null, ikm, info, 32),
                "null salt must derive identically to an explicit 32-byte zero salt");
    }
}
