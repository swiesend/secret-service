package de.swiesend.secretservice.hardened;

import java.util.Optional;

/**
 * Pluggable source of wrapping-key material for the hardened layer.
 *
 * <p>Implementations supply the pepper (mandatory) and, optionally, a TOTP seed.
 * Each implementation must honestly declare its {@link ThreatCoverage} so the builder
 * can refuse weak defaults in production.</p>
 *
 * <p>Callers receive fresh byte/char arrays that they are expected to zero after use.
 * Callbacks inside {@code HardenedCollection} do this automatically.</p>
 */
public interface KeyMaterialProvider {

    /**
     * Retrieve the application pepper. The returned array is owned by the caller and
     * must be zeroed after use (typically by {@code HardenedCollection} in a finally block).
     *
     * @return a fresh copy of the pepper; must not be empty
     * @throws IllegalStateException if the pepper cannot be obtained (fail-closed)
     */
    char[] getPepper();

    /**
     * Retrieve the TOTP seed. Empty means time-binding is disabled for this provider.
     *
     * @return a fresh copy of the seed, or {@code Optional.empty()} for {@code NO_TOTP} mode
     */
    default Optional<byte[]> getTotpSeed() { return Optional.empty(); }

    /**
     * TOTP step counter to use. Default is the current 30-second step.
     */
    default long currentStep() { return Totp.currentStep(); }

    /**
     * Mode this provider operates in. Auto-selects based on {@link #getTotpSeed()} presence.
     */
    default Mode mode() {
        return getTotpSeed().isPresent() ? Mode.STORED_STEP : Mode.NO_TOTP;
    }

    /**
     * Honest self-assessment of the protection this provider actually delivers.
     */
    ThreatCoverage threatCoverage();

    enum Mode {
        /** No time-binding; salt + pepper + KEM only. */
        NO_TOTP,
        /** Step counter is stored in item attributes; read derives HOTP(seed, stored_step). */
        STORED_STEP,
        /** Step counter is not stored; read must occur within +/-1 step. */
        LIVE_CODE
    }
}
