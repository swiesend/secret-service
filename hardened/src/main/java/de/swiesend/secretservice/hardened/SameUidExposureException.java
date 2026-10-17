package de.swiesend.secretservice.hardened;

/**
 * Thrown by {@code HardenedCollection.Builder#build()} when the configured
 * {@link KeyMaterialProvider} reports {@link ThreatCoverage#hasNoSameUidProtection()} -- i.e. its
 * key material is readable by any process running as the same OS user -- and the caller has not
 * accepted that risk via {@code acknowledgeSameUidExposure(true)}.
 *
 * <p>This is a configuration error, not a crypto failure. The encryption itself is unaffected: what
 * the builder refuses is the <em>claim</em> that such a deployment protects secrets from a
 * same-UID attacker.</p>
 */
public class SameUidExposureException extends IllegalStateException {
    public SameUidExposureException(String message) { super(message); }
}
