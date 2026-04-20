package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Console;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Prompts the user at construction time for the pepper (and, optionally, the base64 TOTP seed),
 * then holds the material in memory for the process lifetime. Stronger against offline
 * exfiltration than env-var/file providers; still weak against live same-UID {@code ptrace}.
 *
 * <p>This provider uses {@link System#console()} which returns null in non-TTY environments —
 * it is therefore unsuitable for headless services. Use {@link FileKeyMaterialProvider} there.</p>
 */
public final class InteractiveKeyMaterialProvider implements KeyMaterialProvider {

    private static final Logger log = LoggerFactory.getLogger(InteractiveKeyMaterialProvider.class);

    private final char[] pepper;
    private final byte[] totpSeed;

    /** Reads pepper and optional TOTP seed from the console. */
    public InteractiveKeyMaterialProvider() {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException(
                "no attached TTY; InteractiveKeyMaterialProvider requires a console. "
                        + "Use FileKeyMaterialProvider for headless environments.");
        }
        this.pepper = console.readPassword("secret-service pepper: ");
        if (pepper == null || pepper.length == 0) {
            throw new IllegalStateException("empty pepper entered");
        }
        char[] seedLine = console.readPassword("TOTP seed (base64, empty for none): ");
        if (seedLine == null || seedLine.length == 0) {
            this.totpSeed = null;
        } else {
            byte[] decoded;
            try {
                decoded = java.util.Base64.getDecoder().decode(new String(seedLine));
            } catch (IllegalArgumentException e) {
                Arrays.fill(seedLine, '\0');
                throw new IllegalStateException("TOTP seed was not valid base64", e);
            }
            Arrays.fill(seedLine, '\0');
            this.totpSeed = decoded;
        }
        log.info("InteractiveKeyMaterialProvider initialised; pepper held in JVM memory for the process lifetime.");
    }

    /** Package-private constructor for tests. */
    InteractiveKeyMaterialProvider(char[] pepper, byte[] totpSeed) {
        this.pepper = Objects.requireNonNull(pepper, "pepper").clone();
        this.totpSeed = totpSeed == null ? null : totpSeed.clone();
    }

    @Override public char[] getPepper() { return pepper.clone(); }

    @Override
    public Optional<byte[]> getTotpSeed() {
        return totpSeed == null ? Optional.empty() : Optional.of(totpSeed.clone());
    }

    @Override
    public Mode mode() {
        return totpSeed == null ? Mode.NO_TOTP : Mode.STORED_STEP;
    }

    @Override
    public ThreatCoverage threatCoverage() {
        return new ThreatCoverage(
                ThreatCoverage.Level.PARTIAL,
                ThreatCoverage.Level.REAL,
                ThreatCoverage.Level.REAL,
                ThreatCoverage.Level.NOT_APPLICABLE,
                "Prompted pepper kept in JVM heap; defeats offline backup theft and cross-UID readers, "
                        + "but live same-UID attackers with /proc/<pid>/mem or ptrace still recover it."
        );
    }
}
