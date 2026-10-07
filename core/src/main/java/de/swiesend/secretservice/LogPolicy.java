package de.swiesend.secretservice;

/**
 * What the library is willing to put into a log message.
 *
 * <p>Governed here: human-chosen names ({@link #label}), a value the library holds but did not
 * author. They are off by default and can be switched on for debugging.</p>
 *
 * <h2>Item labels and collection names</h2>
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
        // One parser for both sources, so -Dde.swiesend.secretservice.log.labels=1 and
        // SECRET_SERVICE_LOG_LABELS=1 mean the same: two parsers would disagree without any
        // diagnostic, in the one situation the switch exists for. An unrecognised value ("yes")
        // is not a setting: it neither turns labels off nor hides the env var behind it.
        Boolean fromProperty = parseFlag(System.getProperty(PROPERTY));
        if (fromProperty != null) return fromProperty;
        Boolean fromEnv = parseFlag(System.getenv(ENV));
        return fromEnv != null && fromEnv;
    }

    /** "true"/"1" on, "false"/"0" off, anything else not a setting. */
    private static Boolean parseFlag(String raw) {
        if (raw == null) return null;
        String v = raw.trim().toLowerCase(java.util.Locale.ROOT);
        if (v.equals("true") || v.equals("1")) return Boolean.TRUE;
        if (v.equals("false") || v.equals("0")) return Boolean.FALSE;
        return null;
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
     *
     * <p>Use it wherever the path is known, as the collection lock and unlock messages do: a path
     * is strictly more useful to an operator than {@link #HIDDEN}. A site that logs on a failure
     * path reached <em>before</em> the item or collection exists -- encryption failed, the create
     * call returned nothing, the prompt was dismissed -- has no path to name and uses
     * {@link #label(String)}.</p>
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
