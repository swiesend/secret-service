package de.swiesend.secretservice.hardened;

/**
 * Pluggable source of wrapping-key material for the hardened layer.
 *
 * <p>Implementations supply the pepper. Each implementation must honestly declare its
 * {@link ThreatCoverage} so the builder can refuse weak defaults in production.</p>
 *
 * <p>Callers receive fresh byte/char arrays that they are expected to zero after use.
 * Callbacks inside {@code HardenedCollection} do this automatically.</p>
 *
 * <p>The interface extends {@link AutoCloseable} so providers that hold sensitive
 * material (cached pepper, open TPM handles, etc.) can scrub themselves on shutdown.
 * The default {@link #close()} is a no-op for stateless providers; implementations
 * that hold state should override it. {@link HardenedCollection#close()} propagates
 * to its provider so a try-with-resources on the wrapper is sufficient.</p>
 *
 * <p><b>History:</b> earlier alphas carried an optional TOTP factor here
 * ({@code getTotpSeed()}, {@code currentStep()}, a {@code Mode} enum). It was removed:
 * the {@code STORED_STEP} mode was security theater in every configuration (the step was
 * stored beside the ciphertext and the seed co-located with the pepper, so any attacker
 * holding the key material recomputed the factor), and {@code LIVE_CODE} was only a
 * liveness window — never a possession factor — because the SPI exposed the raw seed to
 * the process. See the 2026-07 security audit, finding F-5.</p>
 */
public interface KeyMaterialProvider extends AutoCloseable {

    /**
     * Retrieve the application pepper. The returned array is owned by the caller and
     * must be zeroed after use (typically by {@code HardenedCollection} in a finally block).
     *
     * @return a fresh copy of the pepper; must not be empty
     * @throws IllegalStateException if the pepper cannot be obtained (fail-closed)
     */
    char[] getPepper();

    /**
     * Honest self-assessment of the protection this provider actually delivers.
     */
    ThreatCoverage threatCoverage();

    /**
     * Release any sensitive material the provider holds (cached peppers, TPM handles,
     * etc.). The default is a no-op so stateless providers do not need to implement it.
     * Re-throws as unchecked because most provider {@code close()} paths cannot fail
     * meaningfully and forcing checked-exception handling on every consumer is noise.
     */
    @Override
    default void close() {}
}
