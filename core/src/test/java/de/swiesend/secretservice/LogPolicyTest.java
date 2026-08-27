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
    void aMissingLabelDoesNotRenderAsNull() {
        LogPolicy.setLabelsLogged(true);
        assertEquals("<no label>", LogPolicy.label(null).toString());
        LogPolicy.setLabelsLogged(false);
        assertEquals(LogPolicy.HIDDEN, LogPolicy.label(null).toString());
    }
}
