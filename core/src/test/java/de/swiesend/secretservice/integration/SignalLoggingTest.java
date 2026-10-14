package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the default log level, INFO, writes about the signals the library receives: nothing. The
 * library receives collection and prompt signals for every application on the bus, and on
 * gnome-keyring a collection's object path is derived from its label.
 */
class SignalLoggingTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    @Test
    void aReceivedSignalIsNotLoggedAtInfo() throws Exception {
        PrintStream original = System.err;   // where slf4j-simple writes
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            CollectionInterface collection = harness.start(true);
            harness.fake().setDismissPrompts(true);
            // The fake answers the unlock prompt with a Completed signal that says "dismissed".
            assertFalse(collection.unlockItem(FakeSecretService.ITEM_PATH), "the user dismissed the prompt");
        } finally {
            System.setErr(original);
        }
        String log = captured.toString(StandardCharsets.UTF_8);

        // Proof that the signal arrived and was handled; without it the check below passes vacuously.
        assertTrue(log.contains("was dismissed by the user"), "the Completed signal was received");
        assertFalse(log.contains("Received signal"), "a received signal must not be logged at INFO");
    }
}
