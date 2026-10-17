package de.swiesend.secretservice.hardened;

/**
 * Per-attacker-class rating of a {@link KeyMaterialProvider}'s effective protection.
 *
 * <p>This is a self-reported honesty signal; it does not enforce anything on its own.
 * The {@code HardenedCollection.Builder} uses it to refuse a provider with no same-UID
 * protection unless the caller explicitly accepts that exposure.</p>
 */
public record ThreatCoverage(Level sameUid, Level crossUid, Level offline, Level networkHndl, String rationale) {

    public enum Level {
        /** Attacker trivially bypasses this mitigation. */
        NONE,
        /** Partial barrier — non-trivial but defeat is practical with some effort. */
        PARTIAL,
        /** Real cryptographic/forensic barrier for this attacker class. */
        REAL,
        /** Mitigation does not apply to this attacker class. */
        NOT_APPLICABLE
    }

    /**
     * True when this provider offers no defence at all against an attacker running as the same OS
     * user -- its key material sits somewhere that attacker can simply read. The builder refuses
     * such a provider unless the caller accepts the risk with
     * {@code acknowledgeSameUidExposure(true)}.
     */
    public boolean hasNoSameUidProtection() {
        return sameUid == Level.NONE;
    }
}
