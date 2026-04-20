package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HybridKemTest {

    @Test
    void generatesX25519Keypair() {
        HybridKem kem = new HybridKem(false);
        KeyPair kp = kem.generateEpochKeyPair();
        assertNotNull(kp.getPublic());
        assertNotNull(kp.getPrivate());
        // Some JDKs report the parent algorithm "XDH" instead of the curve-specific "X25519".
        String alg = kp.getPublic().getAlgorithm();
        assertTrue("X25519".equals(alg) || "XDH".equals(alg), "unexpected algorithm: " + alg);
    }

    @Test
    void classicalEncapDecapRoundTrip() {
        HybridKem kem = new HybridKem(false);
        KeyPair epoch = kem.generateEpochKeyPair();
        HybridKem.Encapsulation e = kem.encapsulate(epoch.getPublic());

        byte[] decapped = kem.decapsulate(epoch.getPrivate(), e.kemCiphertext(), false);
        assertArrayEquals(e.sharedSecret(), decapped);
    }

    @Test
    void postQuantumFlagIsHonest() {
        HybridKem kemRequested = new HybridKem(true);
        // On JDK 21 ML-KEM is absent; probe must report false and algorithm should fall back.
        // We do not assert true/false here, only that the declared algorithm label matches the probe.
        if (kemRequested.postQuantumAvailable()) {
            assertEquals("x25519+ml-kem-768", kemRequested.algorithmLabel());
        } else {
            assertEquals("x25519", kemRequested.algorithmLabel());
        }
    }

    @Test
    void disabledPqAlwaysReportsClassicalOnly() {
        HybridKem kem = new HybridKem(false);
        assertFalse(kem.postQuantumAvailable());
        assertEquals("x25519", kem.algorithmLabel());
    }

    @Test
    void exportImportKeypair() {
        HybridKem kem = new HybridKem(false);
        KeyPair kp = kem.generateEpochKeyPair();
        byte[] pubEnc  = HybridKem.exportPublic(kp.getPublic());
        byte[] privEnc = HybridKem.exportPrivate(kp.getPrivate());
        assertTrue(pubEnc.length > 0);
        assertTrue(privEnc.length > 0);
        assertNotNull(HybridKem.importPublic(pubEnc));
        assertNotNull(HybridKem.importPrivate(privEnc));
    }
}
