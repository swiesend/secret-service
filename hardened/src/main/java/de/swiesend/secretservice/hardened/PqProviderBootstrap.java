package de.swiesend.secretservice.hardened;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KEM;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Availability probe for ML-KEM-768 via the standard {@link javax.crypto.KEM} SPI.
 *
 * <p>This module targets JDK 25, where ML-KEM-768 is provided natively by the stock SunJCE
 * provider (JEP 496, final in JDK 24). There is therefore no third-party provider to register and
 * no global JVM security-state mutation -- unlike earlier revisions that reflectively loaded
 * BouncyCastle on JDK 21-23. This class remains only as a small cached probe so {@link HybridKem}
 * can report {@link HybridKem#postQuantumAvailable()} honestly on the rare JDK build that ships
 * without ML-KEM.</p>
 */
public final class PqProviderBootstrap {

    private static final Logger log = LoggerFactory.getLogger(PqProviderBootstrap.class);

    /** The JCE algorithm name for the ML-KEM parameter set this library uses. */
    static final String ML_KEM_768 = "ML-KEM-768";

    private static final AtomicReference<Boolean> RESULT = new AtomicReference<>();

    private PqProviderBootstrap() {}

    /**
     * Idempotent: {@code true} iff the JVM exposes ML-KEM-768 through {@link javax.crypto.KEM}.
     * On JDK 24+ this is the stock SunJCE algorithm, so the probe succeeds without any setup.
     */
    public static synchronized boolean ensurePqProvider() {
        Boolean cached = RESULT.get();
        if (cached != null) return cached;
        boolean ok;
        try {
            KEM.getInstance(ML_KEM_768);
            ok = true;
        } catch (GeneralSecurityException e) {
            ok = false;
            log.warn("PqProviderBootstrap: ML-KEM-768 not available via javax.crypto.KEM on this "
                    + "runtime ({}); falling back to X25519-only.", e.toString());
        }
        RESULT.set(ok);
        return ok;
    }

    /** The ML-KEM-768 JCE algorithm name, or {@code null} when it is unavailable. */
    public static String mlKem768Algorithm() {
        return ensurePqProvider() ? ML_KEM_768 : null;
    }

    /** Test hook: clear the cached result so subsequent calls re-probe. */
    static void resetForTesting() {
        RESULT.set(null);
    }
}
