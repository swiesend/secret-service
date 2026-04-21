package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TotpTest {

    @Test
    void currentStepIsDeterministicForFixedInstant() {
        // T=59 -> step 1 with 30s window (59/30 = 1)
        assertEquals(1L, Totp.currentStep(59_000L, 30L));
        assertEquals(2L, Totp.currentStep(60_000L, 30L));
        assertEquals(2L, Totp.currentStep(89_000L, 30L));
    }

    @Test
    void stepValidatesPositive() {
        assertThrows(IllegalArgumentException.class, () -> Totp.currentStep(0L, 0L));
        assertThrows(IllegalArgumentException.class, () -> Totp.currentStep(0L, -1L));
    }

    @Test
    void codeIsDeterministicAndLengthRespected() {
        byte[] seed = "12345678901234567890".getBytes();
        byte[] a = Totp.code(seed, 1L, 8);
        byte[] b = Totp.code(seed, 1L, 8);
        assertArrayEquals(a, b);
        assertEquals(8, a.length);
    }

    @Test
    void codeChangesWithStep() {
        byte[] seed = "seed-bytes".getBytes();
        byte[] a = Totp.code(seed, 1L, 16);
        byte[] b = Totp.code(seed, 2L, 16);
        assertFalse(Arrays.equals(a, b));
    }

    @Test
    void codeChangesWithSeed() {
        byte[] seedA = "seed-a".getBytes();
        byte[] seedB = "seed-b".getBytes();
        assertNotEquals(
                Arrays.toString(Totp.code(seedA, 1L, 8)),
                Arrays.toString(Totp.code(seedB, 1L, 8))
        );
    }

    @Test
    void rejectsEmptySeedAndBadSize() {
        assertThrows(IllegalArgumentException.class, () -> Totp.code(new byte[0], 1L, 8));
        assertThrows(IllegalArgumentException.class, () -> Totp.code("s".getBytes(), 1L, 0));
        assertThrows(IllegalArgumentException.class, () -> Totp.code("s".getBytes(), 1L, 33));
    }
}
