package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Reads the pepper from {@code SECRET_SERVICE_PEPPER}.
 *
 * <p><b>Security note — intentional theater against same-UID attackers:</b> any process
 * running as the same UID can read {@code /proc/<pid>/environ} and recover the pepper.
 * This provider is therefore suitable only for CI and development. Its
 * {@link ThreatCoverage#sameUid()} reports {@code NONE} so the builder refuses it in
 * production unless {@code acknowledgeSameUidExposure(true)} is set.</p>
 *
 * <p><b>Unzeroable backing:</b> {@code System.getenv()} has already materialised the pepper
 * as an immutable {@link String} inside the JVM environment map before this provider sees
 * it. We copy it to a local {@code char[]} so subsequent access does not bounce through
 * another {@code String}, but the original env-var String is outside our control and stays
 * in memory until GC decides. This is consistent with, and a reason for, the
 * {@code sameUid=NONE} rating — if you need real memory hygiene, use a provider whose
 * backing never goes through an immutable Java string (file, TPM, HSM, interactive).</p>
 */
public final class EnvVarKeyMaterialProvider implements KeyMaterialProvider {

    private static final Logger log = LoggerFactory.getLogger(EnvVarKeyMaterialProvider.class);

    public static final String ENV_PEPPER = "SECRET_SERVICE_PEPPER";

    // The pepper lives here as a char[]. getPepper() clones it on each call so callers
    // can zero their copy; the field itself is still subject to the class Javadoc's
    // unzeroable-backing caveat because the source String (from System.getenv) lives
    // outside this instance and cannot be scrubbed.
    private final char[] pepperChars;
    private volatile boolean closed = false;

    public EnvVarKeyMaterialProvider() {
        this(System.getenv(ENV_PEPPER));
    }

    /**
     * Construct with an explicit pepper (useful for tests and for callers that source the pepper
     * from a custom location). Fails closed if the pepper is null or empty.
     */
    public EnvVarKeyMaterialProvider(String rawPepper) {
        if (rawPepper == null || rawPepper.isEmpty()) {
            throw new IllegalStateException(
                "SECRET_SERVICE_PEPPER is unset. EnvVarKeyMaterialProvider fails closed rather than "
                        + "silently using a weak or empty pepper. Set the env var, or choose a different provider.");
        }
        this.pepperChars = rawPepper.toCharArray();
        log.warn("SECURITY WARNING: EnvVarKeyMaterialProvider in use. Env-var pepper is readable via "
                + "/proc/<pid>/environ by any same-UID process. Suitable for CI/development only; "
                + "threat_coverage.sameUid=NONE.");
    }

    @Override
    public char[] getPepper() {
        if (closed) throw new IllegalStateException("provider closed");
        char[] out = pepperChars.clone();  // fresh; caller zeros in a finally block
        // Re-check AFTER the copy: a close() racing this call could have zeroed the cache between
        // the guard and the clone, and `out` would then be an all-zero "pepper" -- which seals
        // items under a key nothing can reproduce. Silent, permanent data loss where the guard
        // above was meant to raise. Fail loudly instead.
        if (closed) {
            Arrays.fill(out, '\0');
            throw new IllegalStateException("provider closed");
        }
        return out;
    }

    @Override
    public ThreatCoverage threatCoverage() {
        return new ThreatCoverage(
                ThreatCoverage.Level.NONE,
                ThreatCoverage.Level.NONE,
                ThreatCoverage.Level.NONE,
                ThreatCoverage.Level.NOT_APPLICABLE,
                "Env-var pepper co-located with the ciphertext trust domain; any same-UID reader "
                        + "of /proc/<pid>/environ or the process environment block defeats this provider."
        );
    }

    /**
     * Scrubs the provider's {@code char[]} copy of the pepper. Note the unzeroable-backing caveat
     * in the class Javadoc: the original {@code System.getenv} String is outside this instance and
     * cannot be cleared here.
     */
    @Override
    public void close() {
        // closed FIRST, then zero: the other order lets a concurrent getPepper() pass the guard and
        // then read the array we are about to blank. See the re-check in getPepper().
        closed = true;
        Arrays.fill(pepperChars, '\0');
    }

    /** Utility for tests and ops: generate a cryptographically-strong base64 pepper. */
    public static String generatePepper() {
        byte[] raw = new byte[32];
        new java.security.SecureRandom().nextBytes(raw);
        return new String(Base64.getEncoder().encode(raw), StandardCharsets.US_ASCII);
    }
}
