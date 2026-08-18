package de.swiesend.secretservice.hardened;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Operator-facing diagnostic that exercises the configured {@link HardenedCollection}
 * and reports its posture in a single record. Intended for /healthz endpoints, startup
 * smoke tests, and ad-hoc CLI checks. Does not write to the keyring; reads at most one
 * canary item.
 *
 * <p>Three things this surfaces that nothing else in the API does:</p>
 * <ol>
 *   <li>The provider's {@link ThreatCoverage} — same data the constructor logs at INFO,
 *       but as a structured record callers can render however they want.</li>
 *   <li>JVM-flag warnings: missing {@code -XX:+DisableAttachMechanism},
 *       {@code -XX:-HeapDumpOnOutOfMemoryError}, and the (unenforceable from JVM)
 *       {@code ulimit -c 0} situation.</li>
 *   <li>Round-trip exercise: when a {@code canaryItemPath} is supplied, the check decrypts
 *       it via {@link HardenedCollection#withSecret} and reports success/failure. This is
 *       the only thing that proves "yes, my TPM-sealed pepper is reachable and the
 *       EpochKeystore is intact."</li>
 * </ol>
 *
 * <p>Use as part of a /healthz handler:</p>
 * <pre>
 * HardenedHealthCheck.Report r = HardenedHealthCheck.check(coll, "/path/to/canary");
 * if (!r.healthy()) {
 *     response.status(503).body(r.toReport());
 * }
 * </pre>
 *
 * <p>This class ships no CLI. Applications that want one wire up a provider, wrap a
 * collection, call {@link #check(HardenedCollection, String)} and choose their own exit
 * code from {@link Report#healthy()}.</p>
 */
public final class HardenedHealthCheck {

    private static final Logger log = LoggerFactory.getLogger(HardenedHealthCheck.class);

    /** Severity of a single check finding. {@link Severity#WARN} is informational; {@link Severity#FAIL} is a hard failure. */
    public enum Severity { OK, WARN, FAIL }

    /** A single named finding. */
    public record Finding(String check, Severity severity, String detail) {}

    /**
     * Aggregate report. {@link #healthy()} is true iff no finding has {@link Severity#FAIL}. A provider
     * whose {@code sameUid} threat coverage is {@code NONE} (e.g. {@code EnvVarKeyMaterialProvider})
     * produces a FAIL, so a weak-but-decrypting CI/dev deployment reports UNHEALTHY -- "healthy" means
     * "hardened and decrypting," not merely "decrypting." Missing JVM-hardening flags remain WARN.
     */
    public record Report(
            String providerClass,
            ThreatCoverage threatCoverage,
            String epochId,
            boolean canaryAttempted,
            boolean canarySucceeded,
            List<Finding> findings) {

        public boolean healthy() {
            return findings.stream().noneMatch(f -> f.severity() == Severity.FAIL);
        }

        /** Returns the report rendered as a multi-line operator-readable string. */
        public String toReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("HardenedCollection health: ").append(healthy() ? "HEALTHY" : "UNHEALTHY").append('\n');
            sb.append("  provider:        ").append(providerClass).append('\n');
            sb.append("  epoch:           ").append(epochId).append('\n');
            sb.append("  threat coverage: sameUid=").append(threatCoverage.sameUid())
              .append(", crossUid=").append(threatCoverage.crossUid())
              .append(", offline=").append(threatCoverage.offline())
              .append(", networkHndl=").append(threatCoverage.networkHndl()).append('\n');
            sb.append("  rationale:       ").append(threatCoverage.rationale()).append('\n');
            if (canaryAttempted) {
                sb.append("  canary read:     ").append(canarySucceeded ? "OK" : "FAILED").append('\n');
            } else {
                sb.append("  canary read:     not attempted (no path supplied)\n");
            }
            if (findings.isEmpty()) {
                sb.append("  findings:        none\n");
            } else {
                sb.append("  findings:\n");
                for (Finding f : findings) {
                    sb.append("    [").append(f.severity()).append("] ")
                      .append(f.check()).append(" -- ").append(f.detail()).append('\n');
                }
            }
            return sb.toString();
        }
    }

    private HardenedHealthCheck() {}

    /**
     * Run the health check against a configured collection.
     *
     * @param coll              the live {@link HardenedCollection} to inspect; not closed by this method
     * @param canaryItemPath    optional D-Bus object path of a known-good item to decrypt;
     *                          {@code null} or empty skips the round-trip exercise
     * @return a populated {@link Report} -- never {@code null}
     */
    public static Report check(HardenedCollection coll, String canaryItemPath) {
        Objects.requireNonNull(coll, "coll");
        HardenedStatus status = coll.status();
        String providerClass = coll.providerClassName();
        List<Finding> findings = new ArrayList<>();

        // 1. Provider posture -- a same-UID coverage of NONE is a hard FAIL: the provider offers no
        // defense against the very attacker class a keyring most needs protecting from (CVE-2018-19358).
        // A canary that decrypts does not make such a deployment "healthy"; only CI/dev builds should
        // see this, and they should not be calling the health check green.
        ThreatCoverage tc = status.threatCoverage();
        if (tc.sameUid() == ThreatCoverage.Level.NONE) {
            findings.add(new Finding("provider.sameUid", Severity.FAIL,
                    "Same-UID threat coverage is NONE -- this provider offers no same-UID defense and is "
                            + "suitable only for CI/dev. For production switch to Tpm2KeyMaterialProvider. "
                            + "Wrapping with Argon2KeyMaterialProvider will NOT clear this finding: it "
                            + "stretches a weak pepper against offline guessing but passes same-UID "
                            + "coverage through unchanged."));
        }

        // 2. JVM-flag posture
        List<String> jvmArgs = ManagementFactory.getRuntimeMXBean().getInputArguments();
        boolean attachDisabled = jvmArgs.stream().anyMatch(a -> a.equals("-XX:+DisableAttachMechanism"));
        if (!attachDisabled) {
            findings.add(new Finding("jvm.attach", Severity.WARN,
                    "-XX:+DisableAttachMechanism is not set; jstack/jmap/jcmd from the same UID can read JVM heap. "
                            + "Add it to the JVM launcher to defend against same-UID JVM-attach attackers."));
        }
        boolean heapDumpDisabled = jvmArgs.stream().anyMatch(a -> a.equals("-XX:-HeapDumpOnOutOfMemoryError"));
        if (!heapDumpDisabled) {
            findings.add(new Finding("jvm.heapdump", Severity.WARN,
                    "-XX:-HeapDumpOnOutOfMemoryError is not set; an OOM produces a heap dump on disk that "
                            + "contains every plaintext currently in scope. Disable it for secret-handling daemons."));
        }
        // ulimit -c 0 is not visible from the JVM -- mention it in the rationale rather than checking
        findings.add(new Finding("os.coredump", Severity.OK,
                "ulimit -c 0 (or systemd LimitCORE=0) cannot be inspected from the JVM; verify externally."));

        // 3. Canary round-trip
        boolean canaryAttempted = canaryItemPath != null && !canaryItemPath.isBlank();
        boolean canarySucceeded = false;
        if (canaryAttempted) {
            try {
                Optional<Boolean> ok = coll.withSecret(canaryItemPath, chars -> Boolean.TRUE);
                if (ok.isPresent() && ok.get()) {
                    canarySucceeded = true;
                    findings.add(new Finding("canary.read", Severity.OK,
                            "Canary item " + canaryItemPath + " decrypted successfully."));
                } else {
                    findings.add(new Finding("canary.read", Severity.FAIL,
                            "Canary item " + canaryItemPath + " could not be decrypted. "
                                    + "Check provider, keystore presence, and item attributes."));
                }
            } catch (RuntimeException e) {
                findings.add(new Finding("canary.read", Severity.FAIL,
                        "Canary read threw: " + e.getClass().getSimpleName() + " -- " + e.getMessage()));
            }
        }

        Report report = new Report(
                providerClass, tc, status.epochId(),
                canaryAttempted, canarySucceeded, findings);
        log.info("HardenedHealthCheck: {} ({} findings)",
                report.healthy() ? "healthy" : "UNHEALTHY", findings.size());
        return report;
    }

    /**
     * For use as a structured map (e.g. when serialising to JSON in a /healthz response).
     */
    public static Map<String, Object> toMap(Report r) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("healthy", r.healthy());
        out.put("provider", r.providerClass());
        out.put("epoch", r.epochId());
        out.put("threatCoverage", Map.of(
                "sameUid", r.threatCoverage().sameUid().name(),
                "crossUid", r.threatCoverage().crossUid().name(),
                "offline", r.threatCoverage().offline().name(),
                "networkHndl", r.threatCoverage().networkHndl().name(),
                "rationale", r.threatCoverage().rationale()));
        out.put("canaryAttempted", r.canaryAttempted());
        out.put("canarySucceeded", r.canarySucceeded());
        List<Map<String, String>> findings = new ArrayList<>();
        for (Finding f : r.findings()) {
            findings.add(Map.of("check", f.check(), "severity", f.severity().name(), "detail", f.detail()));
        }
        out.put("findings", findings);
        return out;
    }
}
