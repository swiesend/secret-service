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
        ThreatCoverage threatCoverage,
        String kemAlgorithm,
        String aeadAlgorithm,
        String kdfAlgorithm
) {
    public HardenedStatus {
        Objects.requireNonNull(epochId, "epochId");
        Objects.requireNonNull(threatCoverage, "threatCoverage");
        Objects.requireNonNull(kemAlgorithm, "kemAlgorithm");
        Objects.requireNonNull(aeadAlgorithm, "aeadAlgorithm");
        Objects.requireNonNull(kdfAlgorithm, "kdfAlgorithm");
    }

    /** True if the configuration meaningfully resists the canonical CVE-2018-19358 same-UID attacker. */
    public boolean resistsSameUidAttacker() {
        return threatCoverage.sameUid() == ThreatCoverage.Level.REAL;
    }
}
