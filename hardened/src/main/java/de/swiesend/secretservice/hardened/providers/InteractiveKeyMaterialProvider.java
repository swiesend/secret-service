package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Console;
import java.util.Arrays;
import java.util.Objects;

/**
 * Prompts the user at construction time for the pepper, then holds it in memory for the
 * process lifetime. Stronger against offline exfiltration than env-var/file providers;
 * still weak against live same-UID {@code ptrace}.
 *
 * <p>This provider uses {@link System#console()} which returns null in non-TTY environments —
 * it is therefore unsuitable for headless services. Use {@link FileKeyMaterialProvider} there.</p>
 */
public final class InteractiveKeyMaterialProvider implements KeyMaterialProvider {

    private static final Logger log = LoggerFactory.getLogger(InteractiveKeyMaterialProvider.class);

    private final char[] pepper;
    private volatile boolean closed = false;

    /** Reads the pepper from the console. */
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
        log.info("InteractiveKeyMaterialProvider initialised; pepper held in JVM memory for the process lifetime.");
    }

    /** Package-private constructor for tests. */
    InteractiveKeyMaterialProvider(char[] pepper) {
        this.pepper = Objects.requireNonNull(pepper, "pepper").clone();
    }

    @Override public char[] getPepper() {
        if (closed) throw new IllegalStateException("provider closed");
        return pepper.clone();
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

    /** Scrubs the in-memory pepper. */
    @Override
    public void close() {
        Arrays.fill(pepper, '\0');
        closed = true;
    }
}
