package de.swiesend.secretservice.hardened;

import java.time.Instant;
import java.util.Objects;

/**
 * Runtime status of a {@code HardenedCollection}: which attacker classes are covered, the active
 * cipher suite, whether post-quantum hybrid is in effect, and whether the process memory is locked.
 */
public record HardenedStatus(
        String epochId,
        Instant epochCreated,
        /**
         * Whether the collection's most recent write actually carried an ML-KEM ciphertext -- an
         * observation, not the configured preference. The two differ when an epoch minted before
         * post-quantum was enabled cannot gain its ML-KEM half: writes stay classical while
         * {@code enablePostQuantum(true)} remains set. Before the first write there is nothing to
         * observe and this reports the configured preference.
         */
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
