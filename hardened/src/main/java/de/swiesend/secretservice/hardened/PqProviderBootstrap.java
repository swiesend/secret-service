package de.swiesend.secretservice.hardened;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Reflectively registers BouncyCastle as a JCE provider so that
 * {@code javax.crypto.KEM.getInstance("ML-KEM-768")} succeeds on JDK 21-23 where
 * the stock SunJCE provider does not yet ship ML-KEM (added in JDK 24, JEP 496).
 *
 * <p>Side-effect discipline: this helper is the <b>only</b> place in the library
 * that mutates global JVM security state, and it is invoked only when callers
 * directly construct {@code new HybridKem(true)}. v1 of {@code HardenedCollection}
 * never opts into PQ -- the wrapper currently leaves PQ wiring to a follow-up
 * release, so default consumer flows never load BouncyCastle.</p>
 *
 * <p>BouncyCastle access is reflective so this module compiles and loads without
 * {@code bcprov-jdk18on} on the classpath.</p>
 */
public final class PqProviderBootstrap {

    private static final Logger log = LoggerFactory.getLogger(PqProviderBootstrap.class);
    private static final String BC_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";

    /**
     * Algorithm names to probe, in preference order:
     * <ol>
     *   <li>{@code ML-KEM-768} -- JDK 24+ SunJCE registration, and future BouncyCastle aliases.</li>
     *   <li>{@code ML-KEM} -- BouncyCastle 1.82's generic KEM SPI name (parameter-driven).</li>
     * </ol>
     * The first that succeeds determines what {@link #mlKem768Algorithm()} returns.
     */
    static final String[] ML_KEM_768_NAMES = {"ML-KEM-768", "ML-KEM"};

    private static final AtomicReference<Boolean> RESULT = new AtomicReference<>();
    private static final AtomicReference<String> RESOLVED_ALG = new AtomicReference<>();

    private PqProviderBootstrap() {}

    /**
     * Idempotent: probes whether any known ML-KEM-768 JCE algorithm name succeeds
     * via {@code KEM.getInstance(...)}. If not, attempts to register BouncyCastle
     * as a JCE provider via reflection, then re-probes. Caches the outcome.
     *
     * @return {@code true} if ML-KEM-768 is available after this call
     */
    public static synchronized boolean ensurePqProvider() {
        Boolean cached = RESULT.get();
        if (cached != null) return cached;

        String alg = probe();
        if (alg != null) {
            RESOLVED_ALG.set(alg);
            RESULT.set(Boolean.TRUE);
            return true;
        }

        if (tryRegisterBouncyCastle()) {
            alg = probe();
            if (alg != null) {
                RESOLVED_ALG.set(alg);
                RESULT.set(Boolean.TRUE);
                log.info("PqProviderBootstrap: BouncyCastle registered; ML-KEM-768 available as \"{}\".", alg);
                return true;
            }
            log.warn("PqProviderBootstrap: BouncyCastle was loaded but ML-KEM-768 still missing.");
        }

        RESULT.set(Boolean.FALSE);
        log.warn("PqProviderBootstrap: ML-KEM-768 not available via the standard "
                + "javax.crypto.KEM SPI. Add bcprov-jdk18on 1.82 (or newer) to the "
                + "runtime classpath on JDK 21-23, or run on JDK 24+ where SunJCE "
                + "ships ML-KEM natively. Falling back to X25519-only.");
        return false;
    }

    /**
     * The JCE algorithm name under which ML-KEM-768 was resolved by
     * {@link #ensurePqProvider()}. {@code null} when PQ is unavailable.
     */
    public static String mlKem768Algorithm() {
        ensurePqProvider();
        return RESOLVED_ALG.get();
    }

    /** Test hook: clear the cached result so subsequent calls re-probe. */
    static void resetForTesting() {
        RESULT.set(null);
        RESOLVED_ALG.set(null);
    }

    /** Tries each candidate algorithm name; returns the first that succeeds, else {@code null}. */
    private static String probe() {
        for (String alg : ML_KEM_768_NAMES) {
            if (probeOne(alg)) return alg;
        }
        return null;
    }

    private static boolean probeOne(String alg) {
        try {
            Class<?> kemClass = Class.forName("javax.crypto.KEM");
            kemClass.getMethod("getInstance", String.class).invoke(null, alg);
            return true;
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
