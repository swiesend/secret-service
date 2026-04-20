package de.swiesend.secretservice.hardened;

/**
 * Thrown when a {@code HardenedCollection} is built with a {@link KeyMaterialProvider}
 * whose {@link ThreatCoverage} declares the same-UID attacker is not resisted, and the
 * builder was not given an explicit {@code acknowledgeSecurityTheater(true)} call.
 */
public class SecurityTheaterException extends IllegalStateException {
    public SecurityTheaterException(String message) { super(message); }
}
