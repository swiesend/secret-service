package de.swiesend.secretservice.hardened;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Reflectively registers BouncyCastle as a JCE provider so that
 * {@code javax.crypto.KEM.getInstance("ML-KEM-768")} succeeds on JDK 21-23 where
 * the stock SunJCE provider does not yet ship ML-KEM (added in JDK 24, JEP 496).
 *
 * <p>Side-effect discipline: this helper is the <b>only</b> place in the library
 * that mutates global JVM security state, and it is invoked only when the caller
 * explicitly opts into post-quantum via {@code HardenedCollection.Builder
 * #enablePostQuantum(true)}. Default constructions never load BouncyCastle.</p>
 *
 * <p>BouncyCastle access is reflective so this module compiles and loads without
 * {@code bcprov-jdk18on} on the classpath.</p>
 */
public final class PqProviderBootstrap {

    private static final Logger log = LoggerFactory.getLogger(PqProviderBootstrap.class);
    private static final String BC_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    private static final String ML_KEM_768 = "ML-KEM-768";

    private static final AtomicReference<Boolean> RESULT = new AtomicReference<>();

    private PqProviderBootstrap() {}

    /**
     * Idempotent: probes whether {@code KEM.getInstance("ML-KEM-768")} succeeds.
     * If not, attempts to register BouncyCastle as a JCE provider via reflection,
     * then re-probes. Caches the outcome.
     *
     * @return {@code true} if ML-KEM-768 is available after this call
     */
    public static boolean ensurePqProvider() {
        Boolean cached = RESULT.get();
        if (cached != null) return cached;

        if (probe()) {
            RESULT.compareAndSet(null, Boolean.TRUE);
            return true;
        }

        if (tryRegisterBouncyCastle()) {
            boolean ok = probe();
            RESULT.compareAndSet(null, ok);
            if (ok) {
                log.info("PqProviderBootstrap: BouncyCastle registered; ML-KEM-768 now available.");
            } else {
                log.warn("PqProviderBootstrap: BouncyCastle was loaded but ML-KEM-768 still missing.");
            }
            return ok;
        }

        RESULT.compareAndSet(null, Boolean.FALSE);
        log.warn("PqProviderBootstrap: ML-KEM-768 not available via the standard "
                + "javax.crypto.KEM SPI on this runtime. As of BouncyCastle 1.78.1, BC "
                + "ships ML-KEM/Kyber under `BouncyCastlePQCProvider` but does NOT register "
                + "it through the KEM SPI. Real PQ via the standard API arrives with JDK "
                + "24 (SunJCE ships ML-KEM) or a future BouncyCastle release that wires "
                + "the KEM SPI. Falling back to X25519-only.");
        return false;
    }

    /** Test hook: clear the cached result so subsequent calls re-probe. */
    static void resetForTesting() {
        RESULT.set(null);
    }

    private static boolean probe() {
        try {
            Class<?> kemClass = Class.forName("javax.crypto.KEM");
            kemClass.getMethod("getInstance", String.class).invoke(null, ML_KEM_768);
            return true;
        } catch (ReflectiveOperationException e) {
            // KEM API missing (JDK <21) or ML-KEM not provided
            Throwable cause = e.getCause();
            if (cause instanceof NoSuchAlgorithmException) return false;
            return false;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean tryRegisterBouncyCastle() {
        try {
            // Already registered?
            for (Provider p : Security.getProviders()) {
                if (BC_PROVIDER_CLASS.equals(p.getClass().getName())) return true;
            }
            Class<?> bcClass = Class.forName(BC_PROVIDER_CLASS);
            Provider bc = (Provider) bcClass.getDeclaredConstructor().newInstance();
            Security.addProvider(bc);
            return true;
        } catch (ClassNotFoundException e) {
            return false; // BC dependency simply not present
        } catch (Throwable t) {
            log.warn("PqProviderBootstrap: failed to register BouncyCastle: {}", t.toString());
            return false;
        }
    }
}
