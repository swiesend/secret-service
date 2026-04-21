package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KEM;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
    void ensurePqProviderReportsTruth() throws Exception {
        boolean reported = PqProviderBootstrap.ensurePqProvider();
        boolean reallyAvailable;
        try {
            KEM.getInstance(PqProviderBootstrap.mlKem768Algorithm() != null
                    ? PqProviderBootstrap.mlKem768Algorithm()
                    : "ML-KEM-768");
            reallyAvailable = true;
        } catch (NoSuchAlgorithmException | IllegalArgumentException e) {
            reallyAvailable = false;
        }
        assertEquals(reallyAvailable, reported,
                "ensurePqProvider() must report exactly whether the KEM SPI can produce ML-KEM-768");
    }

    @Test
    void bcProbeSucceedsOnBc182TestClasspath() {
        // With BouncyCastle 1.82 on the test classpath (hardened/pom.xml provided scope),
        // PqProviderBootstrap must be able to register BC and expose ML-KEM via the KEM SPI
        // under either the SunJCE name "ML-KEM-768" or BC's generic "ML-KEM".
        boolean ok = PqProviderBootstrap.ensurePqProvider();
        assertTrue(ok, "BC 1.82 on the classpath should make ML-KEM reachable via javax.crypto.KEM");
        String alg = PqProviderBootstrap.mlKem768Algorithm();
        assertNotNull(alg, "resolved algorithm name must be non-null once PQ is available");
        assertDoesNotThrow(() -> KEM.getInstance(alg),
                "KEM.getInstance(resolved name) must succeed after ensurePqProvider()");
    }
}
