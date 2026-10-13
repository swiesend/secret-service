package de.swiesend.secretservice.hardened.tpm2;

/**
 * Preflight: check whether the TSS.Java library (Microsoft TPM 2.0 TSS for Java,
 * Maven coordinates {@code com.microsoft.azure:TSS.Java:1.0.0}) is reachable on
 * the classpath. Deliberately lives in its own class with <b>no TSS.Java imports
 * at all</b>, so calling {@link #isAvailable()} does not force the classloader
 * to resolve {@code tss.*} types -- which would itself throw
 * {@link NoClassDefFoundError} if the library is missing.
 *
 * <p>Typical use from application startup:</p>
 * <pre>
 * if (!Tpm2Availability.isAvailable()) {
 *     log.warn("TSS.Java is not on the classpath; falling back to "
 *            + "EnvVarKeyMaterialProvider (CI / dev only).");
 *     return new EnvVarKeyMaterialProvider();
 * }
 * return Tpm2KeyMaterialProvider.forPlatformTpm(blob, password);
 * </pre>
 */
public final class Tpm2Availability {

    private Tpm2Availability() {}

    /**
     * @return {@code true} if {@code tss.TpmFactory} resolves via the current
     *         context classloader (i.e. TSS.Java is on the classpath). Does
     *         <i>not</i> open a TPM or touch any device; purely a classpath
     *         probe.
     */
    public static boolean isAvailable() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) cl = Tpm2Availability.class.getClassLoader();
        try {
            // initialize=false: don't run TpmFactory's static initialiser here.
            Class.forName("tss.TpmFactory", false, cl);
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    /**
     * A human-readable string describing how to install TSS.Java if
     * {@link #isAvailable()} returned false. Suitable for including in a
     * startup warning.
     */
    public static String installationHint() {
        return "TSS.Java is required for Tpm2KeyMaterialProvider. "
                + "Add 'com.microsoft.azure:TSS.Java:1.0.0' (Maven Central) to the runtime classpath.";
    }
}
