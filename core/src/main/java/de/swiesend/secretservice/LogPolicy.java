package de.swiesend.secretservice;

/**
 * Whether human-chosen names -- item labels and collection names -- may appear in log messages.
 *
 * <p><b>Off by default.</b> A label is the one piece of an item a person wrote themselves, and it
 * routinely describes the secret it guards: <i>"Bank — savings login"</i>, <i>"prod DB root"</i>,
 * <i>"ex-employer VPN"</i>. Logs travel further than keyrings do -- journald, a CI job's public
 * output, a support bundle -- so the library keeps them out of messages unless you ask for them.
 * Nothing is lost for diagnosis: where the library knows the item's object path it logs that
 * instead, and a path resolves back to the item without naming it.</p>
 *
 * <p>This is <em>not</em> a logging façade. Levels, formats, appenders and per-logger filtering
 * stay entirely with your SLF4J backend; this switch governs one thing, which no backend can
 * undo after the fact — whether the label is placed into the message in the first place.</p>
 *
 * <h2>Turning it on</h2>
 * <p>Any one of these, checked in this order:</p>
 * <ul>
 *   <li>the system property {@value #PROPERTY}, e.g.
 *       {@code java -Dde.swiesend.secretservice.log.labels=true -jar yourapp.jar}</li>
 *   <li>the environment variable {@value #ENV}, set to {@code true} or {@code 1} -- for
 *       containers and unit files, where adding a JVM flag is awkward</li>
 *   <li>{@link #setLabelsLogged(boolean)} at runtime, which overrides both</li>
 * </ul>
 *
 * <p>Turn it on while reproducing a problem, not in steady state. Because the switch is read on
 * every emitted message, {@code setLabelsLogged(true)} can wrap a narrow window and be turned back
 * off, without a restart.</p>
 *
 * <p><b>What this switch never covers.</b> Secrets, peppers and key material are not logged at any
 * setting and have no flag to enable them. Only names are governed here.</p>
 *
 * @since 3.0.0
 */
public final class LogPolicy {

    /** System property enabling labels in log messages: {@code de.swiesend.secretservice.log.labels}. */
    public static final String PROPERTY = "de.swiesend.secretservice.log.labels";

    /** Environment variable enabling labels in log messages: {@code SECRET_SERVICE_LOG_LABELS}. */
    public static final String ENV = "SECRET_SERVICE_LOG_LABELS";

    /** Stand-in printed in place of a label when the path is unknown too. */
    static final String HIDDEN = "<label hidden>";

    private static volatile boolean labelsLogged = readInitialSetting();

    private LogPolicy() {}

    private static boolean readInitialSetting() {
        String prop = System.getProperty(PROPERTY);
        if (prop != null) return Boolean.parseBoolean(prop);
        String env = System.getenv(ENV);
        // "1" as well as "true", matching SECRET_SERVICE_HARDENED_ALLOW_MIGRATION.
        return env != null && ("1".equals(env) || Boolean.parseBoolean(env));
    }

    /** Whether labels and collection names are currently written into log messages. */
    public static boolean labelsLogged() {
        return labelsLogged;
    }

    /**
     * Turns label logging on or off for this JVM, overriding {@link #PROPERTY} and {@link #ENV}.
     * Takes effect on the next message emitted.
     */
    public static void setLabelsLogged(boolean enabled) {
        labelsLogged = enabled;
    }

    /** Re-reads {@link #PROPERTY} / {@link #ENV}, discarding any {@link #setLabelsLogged} override. */
    public static void resetToConfiguredSetting() {
        labelsLogged = readInitialSetting();
    }

    /**
     * A log argument that renders as {@code label} only when label logging is on, and as
     * {@link #HIDDEN} otherwise. Use where no object path is available.
     *
     * <p>The decision happens in {@code toString()}, which SLF4J calls only for a message it
     * actually emits -- so a suppressed statement costs nothing, and a label never reaches a
     * formatter that then discards it.</p>
     */
    public static Object label(String label) {
        return label(label, null);
    }

    /**
     * A log argument that renders as {@code label} when label logging is on, and otherwise as
     * {@code objectPath} -- which identifies the item to an operator without naming it. Falls back
     * to {@link #HIDDEN} when the path is unknown.
     */
    public static Object label(String label, String objectPath) {
        return new LabelArgument(label, objectPath);
    }

    /** Deferred rendering; see {@link #label(String, String)}. */
    private record LabelArgument(String label, String objectPath) {
        @Override
        public String toString() {
            if (labelsLogged) return label == null ? "<no label>" : label;
            return objectPath != null ? objectPath : HIDDEN;
        }
    }
}
