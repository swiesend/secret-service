package de.swiesend.secretservice.hardened;

/**
 * Per-attacker-class rating of a {@link KeyMaterialProvider}'s effective protection.
 *
 * <p>This is a self-reported honesty signal; it does not enforce anything on its own.
 * The {@code HardenedCollection.Builder} uses it to refuse weak providers in production
 * unless the caller explicitly acknowledges security theater.</p>
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

    public boolean isSecurityTheaterVsSameUid() {
        return sameUid == Level.NONE;
    }
}
