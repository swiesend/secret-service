package de.swiesend.secretservice;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Item labels and collection names are user-chosen and routinely describe the secret they guard,
 * so they stay out of log messages unless explicitly enabled. These tests pin the default and the
 * rendering; the property/env plumbing is covered by {@link #systemPropertyEnablesLabels()}.
 */
class LogPolicyTest {

    @AfterEach
    void restoreDefault() {
        System.clearProperty(LogPolicy.PROPERTY);
        LogPolicy.resetToConfiguredSetting();
    }

    @Test
    void labelsAreHiddenByDefault() {
        // The JVM cannot unset an environment variable, and SECRET_SERVICE_LOG_LABELS=true is the
        // documented way to enable labels in a container -- so on a machine configured that way
        // this assertion would fail while both the machine and the code behave as documented.
        // Skipping is the honest answer; the env path itself is untestable in-JVM for the same
        // reason, which is why no test covers it.
        org.junit.jupiter.api.Assumptions.assumeTrue(System.getenv(LogPolicy.ENV) == null,
                LogPolicy.ENV + " is set in this environment, so the default does not apply here");
        LogPolicy.resetToConfiguredSetting();
        assertFalse(LogPolicy.labelsLogged(),
                "labels must be off unless asked for -- logs travel further than keyrings do");
        assertEquals(LogPolicy.HIDDEN, LogPolicy.label("Bank - savings login").toString(),
                "a label with no known path renders as a placeholder, never as itself");
    }

    @Test
    void aKnownObjectPathIsLoggedInPlaceOfTheLabel() {
        // Diagnosability without disclosure: the path identifies the item to an operator, and
        // resolves back to it, without naming what it is.
        LogPolicy.setLabelsLogged(false);
        assertEquals("/org/freedesktop/secrets/collection/login/42",
                LogPolicy.label("prod DB root", "/org/freedesktop/secrets/collection/login/42").toString());
    }

    @Test
    void enablingShowsTheLabelEvenWhenAPathIsKnown() {
        LogPolicy.setLabelsLogged(true);
        assertEquals("prod DB root",
                LogPolicy.label("prod DB root", "/org/freedesktop/secrets/collection/login/42").toString());
        assertEquals("prod DB root", LogPolicy.label("prod DB root").toString());
    }

    @Test
    void systemPropertyEnablesLabels() {
        System.setProperty(LogPolicy.PROPERTY, "true");
        LogPolicy.resetToConfiguredSetting();
        assertTrue(LogPolicy.labelsLogged(), "the system property must be honoured");
        assertEquals("secret-ish name", LogPolicy.label("secret-ish name").toString());

        System.setProperty(LogPolicy.PROPERTY, "false");
        LogPolicy.resetToConfiguredSetting();
        assertFalse(LogPolicy.labelsLogged());
    }

    @Test
    void theRuntimeSwitchOverridesConfigurationAndCanBeRestored() {
        // Turn on for a narrow window while reproducing a problem, then back off -- no restart.
        System.setProperty(LogPolicy.PROPERTY, "false");
        LogPolicy.resetToConfiguredSetting();
        assertFalse(LogPolicy.labelsLogged());

        LogPolicy.setLabelsLogged(true);
        assertTrue(LogPolicy.labelsLogged(), "the runtime override wins over the property");

        LogPolicy.resetToConfiguredSetting();
        assertFalse(LogPolicy.labelsLogged(), "resetting discards the override");
    }

    @Test
    void renderingIsDeferredUntilTheMessageIsActuallyEmitted() {
        // SLF4J calls toString() only for a message it emits, so the label is never assembled for a
        // statement the backend discards. Pinning it here keeps a future refactor from switching
        // back to eager String.format, which would build the label regardless.
        LogPolicy.setLabelsLogged(false);
        Object arg = LogPolicy.label("never rendered");
        assertFalse(arg instanceof String,
                "label() must return a lazily-rendering argument, not an already-built String");
    }

    @Test
    void aThirdPartyFailureRendersAsItsTypeAndNeverItsMessage() {
        // A KeyMaterialProvider builds its exception message from whatever it has to hand, and what
        // it has to hand is the pepper. Logging e.toString() at that boundary would turn someone
        // else's mistake into this library's disclosure. There is deliberately no switch to widen
        // this -- unlike a label, the text was never the user's to disclose.
        Throwable leaky = new IllegalStateException("failed with pepper=hunter2");

        LogPolicy.setLabelsLogged(true);   // even fully permissive, the message must not appear
        String rendered = LogPolicy.cause(leaky).toString();

        assertEquals("java.lang.IllegalStateException", rendered);
        assertFalse(rendered.contains("hunter2"), "a third-party message must never be logged");
        assertEquals("<no cause>", LogPolicy.cause(null).toString());
    }

    @Test
    void aMissingLabelDoesNotRenderAsNull() {
        LogPolicy.setLabelsLogged(true);
        assertEquals("<no label>", LogPolicy.label(null).toString());
        LogPolicy.setLabelsLogged(false);
        assertEquals(LogPolicy.HIDDEN, LogPolicy.label(null).toString());
    }
}
