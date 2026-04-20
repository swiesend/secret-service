package de.swiesend.secretservice.hardened;

import java.time.Instant;
import java.util.Objects;

/**
 * Runtime status of a {@code HardenedCollection}: which factors are active, which attacker
 * classes are covered, and whether post-quantum hybrid is in effect.
 */
public record HardenedStatus(
        String epochId,
        Instant epochCreated,
        boolean postQuantumActive,
        boolean memoryLocked,
        KeyMaterialProvider.Mode totpMode,
        ThreatCoverage threatCoverage,
        String kemAlgorithm,
        String aeadAlgorithm,
        String kdfAlgorithm
) {
    public HardenedStatus {
        Objects.requireNonNull(epochId, "epochId");
        Objects.requireNonNull(totpMode, "totpMode");
        Objects.requireNonNull(threatCoverage, "threatCoverage");
        Objects.requireNonNull(kemAlgorithm, "kemAlgorithm");
        Objects.requireNonNull(aeadAlgorithm, "aeadAlgorithm");
        Objects.requireNonNull(kdfAlgorithm, "kdfAlgorithm");
    }

    /** True if the configuration meaningfully resists the canonical CVE-2018-19358 same-UID attacker. */
    public boolean resistsSameUidAttacker() {
        return threatCoverage.sameUid() == ThreatCoverage.Level.REAL;
    }

    /** Human-readable time-binding label: {@code "none"}, {@code "stored_step (theater)"}, {@code "live_code"}. */
    public String timeBindingLabel() {
        return switch (totpMode) {
            case NO_TOTP -> "none";
            case STORED_STEP -> "stored_step (theater)";
            case LIVE_CODE -> "live_code";
        };
    }
}
