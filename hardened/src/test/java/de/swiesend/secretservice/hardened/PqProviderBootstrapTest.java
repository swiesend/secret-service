package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KEM;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PqProviderBootstrapTest {

    @BeforeEach
    void resetCache() {
        PqProviderBootstrap.resetForTesting();
    }

    @Test
    void ensurePqProviderIsIdempotent() {
        boolean first = PqProviderBootstrap.ensurePqProvider();
        boolean second = PqProviderBootstrap.ensurePqProvider();
        assertEquals(first, second);
    }

    @Test
    void ensurePqProviderReportsTruth() {
        boolean reported = PqProviderBootstrap.ensurePqProvider();
        boolean reallyAvailable;
        try {
            KEM.getInstance("ML-KEM-768");
            reallyAvailable = true;
        } catch (NoSuchAlgorithmException e) {
            reallyAvailable = false;
        }
        assertEquals(reallyAvailable, reported,
                "ensurePqProvider() must report exactly whether the KEM SPI can produce ML-KEM-768");
    }

    @Test
    void mlKemAvailableNativelyWithoutBouncyCastle() throws Exception {
        // JDK 24+ ships ML-KEM-768 in the stock SunJCE provider (JEP 496). This module targets
        // JDK 25, so the probe must succeed with no third-party provider registered for the KEM.
        assertTrue(PqProviderBootstrap.ensurePqProvider(),
                "ML-KEM-768 must be available natively via javax.crypto.KEM on JDK 24+");
        assertEquals("ML-KEM-768", PqProviderBootstrap.mlKem768Algorithm());

        String provider = KeyPairGenerator.getInstance("ML-KEM-768").getProvider().getName();
        assertFalse(provider.toLowerCase().contains("bc") || provider.toLowerCase().contains("bouncy"),
                "ML-KEM-768 must be served by a stock JDK provider, not BouncyCastle (was: " + provider + ")");
    }
}
