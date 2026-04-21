package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

/**
 * Reads the pepper from {@code SECRET_SERVICE_PEPPER} and an optional TOTP seed from
 * {@code SECRET_SERVICE_TOTP_SEED} (base64).
 *
 * <p><b>Security note — intentional theater against same-UID attackers:</b> any process
 * running as the same UID can read {@code /proc/<pid>/environ} and recover these values.
 * This provider is therefore suitable only for CI and development. Its
 * {@link ThreatCoverage#sameUid()} reports {@code NONE} so the builder refuses it in
 * production unless {@code acknowledgeSecurityTheater(true)} is set.</p>
 */
public final class EnvVarKeyMaterialProvider implements KeyMaterialProvider {

    private static final Logger log = LoggerFactory.getLogger(EnvVarKeyMaterialProvider.class);

    public static final String ENV_PEPPER = "SECRET_SERVICE_PEPPER";
    public static final String ENV_TOTP_SEED = "SECRET_SERVICE_TOTP_SEED";
    public static final String ENV_MODE = "SECRET_SERVICE_TOTP_MODE"; // NO_TOTP | STORED_STEP | LIVE_CODE

    private final String pepperSource;
    private final byte[] totpSeed;
    private final Mode mode;

    public EnvVarKeyMaterialProvider() {
        this(System.getenv(ENV_PEPPER), System.getenv(ENV_TOTP_SEED), System.getenv(ENV_MODE));
    }

    /**
     * Construct with explicit values (useful for tests and for callers that source env
     * material from a custom location). Semantics match the env-var path: pepper is
     * mandatory, seed is optional base64, mode overrides the default.
     */
    public EnvVarKeyMaterialProvider(String rawPepper, String rawSeed, String rawMode) {
        if (rawPepper == null || rawPepper.isEmpty()) {
            throw new IllegalStateException(
                "SECRET_SERVICE_PEPPER is unset. EnvVarKeyMaterialProvider fails closed rather than "
                        + "silently using a weak or empty pepper. Set the env var, or choose a different provider.");
        }
        this.pepperSource = rawPepper;
        if (rawSeed == null || rawSeed.isEmpty()) {
            this.totpSeed = null;
            this.mode = Mode.NO_TOTP;
        } else {
            try {
                this.totpSeed = Base64.getDecoder().decode(rawSeed);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException(ENV_TOTP_SEED + " is not valid base64", e);
            }
            Mode parsed = Mode.STORED_STEP;
            if (rawMode != null) {
                try {
                    parsed = Mode.valueOf(rawMode.trim().toUpperCase(Locale.ROOT));
                } catch (IllegalArgumentException ignore) {
                    log.warn("SECRET_SERVICE_TOTP_MODE={} not recognised; defaulting to STORED_STEP", rawMode);
                }
            }
            this.mode = parsed;
        }
        log.warn("SECURITY WARNING: EnvVarKeyMaterialProvider in use. Env-var pepper is readable via "
                + "/proc/<pid>/environ by any same-UID process. Suitable for CI/development only; "
                + "threat_coverage.sameUid=NONE.");
    }

    @Override
    public char[] getPepper() {
        return pepperSource.toCharArray();
    }

    @Override
    public Optional<byte[]> getTotpSeed() {
        return totpSeed == null ? Optional.empty() : Optional.of(totpSeed.clone());
    }

    @Override
    public Mode mode() {
        return mode;
    }

    @Override
    public ThreatCoverage threatCoverage() {
        return new ThreatCoverage(
                ThreatCoverage.Level.NONE,
                ThreatCoverage.Level.NONE,
                ThreatCoverage.Level.NONE,
                ThreatCoverage.Level.NOT_APPLICABLE,
                "Env-var pepper co-located with the ciphertext trust domain; any same-UID reader "
                        + "of /proc/<pid>/environ or the process environment block defeats this provider."
        );
    }

    /** Utility for tests and ops: generate a cryptographically-strong base64 pepper. */
    public static String generatePepper() {
        byte[] raw = new byte[32];
        new java.security.SecureRandom().nextBytes(raw);
        return new String(Base64.getEncoder().encode(raw), StandardCharsets.US_ASCII);
    }
}
