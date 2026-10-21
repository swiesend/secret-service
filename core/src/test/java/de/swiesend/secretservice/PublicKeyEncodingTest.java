package de.swiesend.secretservice;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The specification transfers a Diffie-Hellman public key as an unsigned integer of arbitrary size,
 * most significant byte first. The library sent {@link BigInteger#toByteArray()}, which is as short
 * as the value allows, and KWallet refuses a key of fewer than 128 bytes: about one session in 512,
 * whose key has its top 9 bits clear, failed with "Client public key size is invalid". KWallet reads
 * the key as a signed number, so the sign byte that {@code toByteArray()} gives a key whose top bit
 * is set stays.
 */
class PublicKeyEncodingTest {

    private static final int LENGTH = 128;
    private static final BigInteger PRIME = Static.RFC_2409.SecondOakleyGroup.prime();

    @Test
    void theSpecificationsExampleIsTheSameNumber() {
        // "the integer 32768 is represented as the 2-byte string 0x80 0x00". With the sign byte in
        // front, the bytes read as unsigned are still 32768.
        byte[] bytes = TransportEncryption.toKeyBytes(BigInteger.valueOf(32768), 2);

        assertArrayEquals(new byte[]{0x00, (byte) 0x80, 0x00}, bytes);
        assertEquals(BigInteger.valueOf(32768), new BigInteger(1, bytes));
    }

    @Test
    void aKeyWithAZeroTopByteFillsAllBytes() {
        BigInteger key = BigInteger.ONE.shiftLeft(1010);
        assertEquals(127, key.toByteArray().length, "precondition: the signed form is a byte short");

        byte[] bytes = TransportEncryption.toKeyBytes(key, LENGTH);

        assertEquals(LENGTH, bytes.length);
        assertEquals(0x00, bytes[0]);
        assertEquals(0x04, bytes[1]);
    }

    @Test
    void aKeyWithTheTopBitSetKeepsItsSignByte() {
        BigInteger key = BigInteger.ONE.shiftLeft(1023);

        byte[] bytes = TransportEncryption.toKeyBytes(key, LENGTH);

        assertEquals(LENGTH + 1, bytes.length);
        assertEquals(0x00, bytes[0]);
        assertEquals((byte) 0x80, bytes[1]);
    }

    @Test
    void kwalletNeedsTheSignByteOfAKeyWhoseTopNineBitsAreSet() {
        BigInteger key = PRIME.subtract(BigInteger.ONE.shiftLeft(100));
        byte[] withoutSignByte = new byte[LENGTH];
        byte[] signed = key.toByteArray();
        java.lang.System.arraycopy(signed, 1, withoutSignByte, 0, LENGTH);
        assertNotEquals(key, readAsKWallet(withoutSignByte), "precondition: without it, KWallet reads another key");

        assertEquals(key, readAsKWallet(TransportEncryption.toKeyBytes(key, LENGTH)));
    }

    @Test
    void everyKeyBelowThePrimeIsReadAsItWasSent() {
        Random random = new Random(1);
        for (int i = 0; i < 1500; i++) {
            // A third of the keys have a zero top byte, as one random key in 256 has, and a third
            // have their top 9 bits set, as one in 512 has.
            BigInteger key = switch (i % 3) {
                case 0 -> new BigInteger(1024, random).mod(PRIME);
                case 1 -> new BigInteger(1016, random).setBit(0);
                default -> PRIME.subtract(BigInteger.ONE).subtract(new BigInteger(1014, random));
            };

            byte[] bytes = TransportEncryption.toKeyBytes(key, LENGTH);

            assertTrue(bytes.length >= LENGTH, "at least " + LENGTH + " bytes");
            assertEquals(key, new BigInteger(1, bytes), "as the specification reads it");
            assertEquals(key, readAsKWallet(bytes), "as KWallet reads it");
        }
    }

    @Test
    void aNegativeValueIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> TransportEncryption.toKeyBytes(BigInteger.ONE.negate(), LENGTH));
    }

    /**
     * The key that KWallet computes with for {@code bytes}. QCA's {@code BigInteger} reads them as a
     * signed number, and qca-ossl hands OpenSSL that number's {@code toArray()}: its two's
     * complement in as few bytes as its magnitude takes, a byte more when the magnitude's top bit is
     * set, which {@code BN_bin2bn} reads as unsigned.
     */
    private static BigInteger readAsKWallet(byte[] bytes) {
        BigInteger signed = new BigInteger(bytes);
        BigInteger magnitude = signed.abs();
        int size = Math.max(1, (magnitude.bitLength() + 7) / 8);
        if (magnitude.testBit(8 * size - 1)) size++;
        return signed.signum() < 0 ? signed.add(BigInteger.ONE.shiftLeft(8 * size)) : signed;
    }
}
