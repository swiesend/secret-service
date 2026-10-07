package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

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
        if (kemRequested.postQuantumAvailable()) {
            assertEquals("x25519+ml-kem-768", kemRequested.algorithmLabel());
            assertEquals(KemId.X25519_MLKEM768, kemRequested.kemId());
        } else {
            assertEquals("x25519", kemRequested.algorithmLabel());
            assertEquals(KemId.X25519, kemRequested.kemId());
        }
    }

    @Test
    void disabledPqAlwaysReportsClassicalOnly() {
        HybridKem kem = new HybridKem(false);
        assertFalse(kem.postQuantumAvailable());
        assertEquals("x25519", kem.algorithmLabel());
        // The KEM is always on: a non-PQ instance stamps X25519, never NONE.
        assertEquals(KemId.X25519, kem.kemId());
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

    @Test
    void hybridEncapDecapRoundTrip_whenPqAvailable() {
        HybridKem kem = new HybridKem(true);
        assumeTrue(kem.postQuantumAvailable(),
                "ML-KEM-768 not available on this runtime; skipping hybrid round-trip");

        KeyPair x = kem.generateEpochKeyPair();
        KeyPair pq = kem.generatePqKeyPair();

        HybridKem.Encapsulation e = kem.encapsulate(x.getPublic(), pq.getPublic());
        byte[] decapped = kem.decapsulate(x.getPrivate(), pq.getPrivate(), e.kemCiphertext(), true);
        assertArrayEquals(e.sharedSecret(), decapped);
        assertEquals("x25519+ml-kem-768", kem.algorithmLabel());
    }

    @Test
    void hybridDecapFailsIfFlaggedHybridButCiphertextHasNoPqPart() {
        HybridKem kem = new HybridKem(false);
        KeyPair epoch = kem.generateEpochKeyPair();
        HybridKem.Encapsulation classical = kem.encapsulate(epoch.getPublic());
        // classical kemCiphertext has no PQ part; decapsulating with envelopeIsHybrid=true
        // must reject rather than silently proceed
        Exception ex = org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> kem.decapsulate(epoch.getPrivate(), null, classical.kemCiphertext(), true));
        assertTrue(ex.getMessage().contains("hybrid envelope missing pq ciphertext"));
    }

    @Test
    void packedKemCiphertextHasLengthPrefix() {
        HybridKem kem = new HybridKem(false);
        KeyPair epoch = kem.generateEpochKeyPair();
        HybridKem.Encapsulation e = kem.encapsulate(epoch.getPublic());
        byte[] kemCt = e.kemCiphertext();
        assertTrue(kemCt.length > 2, "kemCiphertext must include uint16 length prefix");
        int x25519Len = ((kemCt[0] & 0xff) << 8) | (kemCt[1] & 0xff);
        assertEquals(kemCt.length - 2, x25519Len, "classical envelope: only x25519 SPKI after the prefix");
    }
}
