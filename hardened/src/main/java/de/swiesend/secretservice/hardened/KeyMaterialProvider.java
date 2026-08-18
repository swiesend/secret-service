package de.swiesend.secretservice.hardened;

/**
 * Pluggable source of wrapping-key material (the "pepper") for the hardened layer.
 *
 * <p>Each implementation must honestly declare its {@link ThreatCoverage} so the builder can refuse
 * weak defaults in production. Callers receive a fresh {@code char[]} they are expected to zero
 * after use; {@code HardenedCollection} does this automatically.</p>
 *
 * <p>The interface extends {@link AutoCloseable} so providers that hold sensitive material (cached
 * pepper, open TPM handles, etc.) can scrub themselves on shutdown. The default {@link #close()} is
 * a no-op for stateless providers; implementations that hold state should override it.
 * <b>You are responsible for closing the provider you construct.</b></p>
 */
public interface KeyMaterialProvider extends AutoCloseable {

    /**
     * Retrieve the application pepper. The returned array is owned by the caller and must be zeroed
     * after use (typically by {@code HardenedCollection} in a finally block).
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
     * Release any sensitive material the provider holds (cached peppers, TPM handles, etc.). The
     * default is a no-op so stateless providers do not need to implement it.
     */
    @Override
    default void close() {}
}
