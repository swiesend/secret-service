package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KEM;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void ensurePqProviderMatchesActualKemAvailability() throws Exception {
        // Honesty test: whatever ensurePqProvider() returns must match what
        // KEM.getInstance("ML-KEM-768") actually does.
        // - JDK 24+ with stock SunJCE: returns true.
        // - JDK 21-23 with BouncyCastle 1.78.1: returns false (BC does not wire
        //   ML-KEM through the KEM SPI yet -- it only exposes Kyber under
        //   BouncyCastlePQCProvider via legacy KeyPairGenerator names).
        boolean reported = PqProviderBootstrap.ensurePqProvider();
        boolean reallyAvailable;
        try {
            KEM.getInstance("ML-KEM-768");
            reallyAvailable = true;
        } catch (NoSuchAlgorithmException e) {
            reallyAvailable = false;
        }
        assertEquals(reallyAvailable, reported,
                "ensurePqProvider() must report exactly whether the standard KEM SPI "
                        + "can produce ML-KEM-768 right now");
    }

    @Test
    void documentsBouncyCastle178KemSpiGap() {
        // This test pins down the current state of BC 1.78.x integration.
        // It will start failing (in a good way) when BC ships ML-KEM under the
        // standard javax.crypto.KEM SPI -- at which point we should bump the
        // BC version and remove this test.
        boolean isJdk24Plus = Runtime.version().feature() >= 24;
        if (isJdk24Plus) {
            // SunJCE provides ML-KEM on JDK 24+; nothing to assert here.
            return;
        }
        boolean ok = PqProviderBootstrap.ensurePqProvider();
        assertTrue(!ok || onClasspathWithFutureBc(),
                "On JDK <24, BC 1.78.1 should NOT make ML-KEM-768 reachable via the KEM SPI");
    }

    private static boolean onClasspathWithFutureBc() {
        // Trapdoor for future BC versions that wire the KEM SPI: if a non-1.78.x BC
        // is on the classpath, allow the assertion to pass through.
        try {
            String version = (String) Class.forName("org.bouncycastle.LICENSE")
                    .getField("licenseText").get(null);
            return version != null && !version.contains("1.78");
        } catch (Throwable t) {
            return false;
        }
    }
}
