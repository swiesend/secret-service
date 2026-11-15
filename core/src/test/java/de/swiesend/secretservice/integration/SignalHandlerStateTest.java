package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.handlers.SignalHandler;
import de.swiesend.secretservice.interfaces.Prompt;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A signal handler's buffer is filled on dbus-java's threads and read on the caller's.
 * {@code disconnect()} emptied the buffer and then reset the handler's path, each on its own: a
 * signal that dbus-java still delivered after it was checked against no path, and stayed in the
 * buffer of a handler that listens to nothing. The buffer itself was handed out as it is, to be
 * read while it changes.
 *
 * <p>On the fixture's bus, with no signal registered: each test hands the handler its signals
 * itself, as dbus-java does.</p>
 */
class SignalHandlerStateTest {

    private static final String PROMPT = FakeSecretService.PROMPT_PATH;
    private static final String OTHER_PROMPT = FakeSecretService.PROMPT_PATH + "2";

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private final SignalHandler handler = new SignalHandler();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        handler.disconnect();
        harness.stop();
    }

    private static Prompt.Completed completed(String path) throws Exception {
        return new Prompt.Completed(path, false, new Variant<>(""));
    }

    @Test
    void aSignalDeliveredAfterTheDisconnectIsNotTaken() throws Exception {
        harness.start(false);
        handler.connect(harness.clientConnection(), List.of(), PROMPT);
        handler.handle(completed(OTHER_PROMPT));
        assertEquals(0, handler.getCount(), "the handler takes the signals of its own path");

        handler.disconnect();
        handler.handle(completed(OTHER_PROMPT));
        handler.handle(completed(PROMPT));

        assertEquals(0, handler.getCount(), "and none once it listens to nothing");
        assertNull(handler.getLastHandledSignal());
        assertTrue(handler.getHandledSignals(Prompt.Completed.class).isEmpty());
    }

    @Test
    void aHandlerThatIsConnectedAgainTakesTheSignalsOfItsNewPath() throws Exception {
        harness.start(false);
        handler.connect(harness.clientConnection(), List.of(), PROMPT);
        handler.handle(completed(PROMPT));
        handler.disconnect();

        handler.connect(harness.clientConnection(), List.of(), OTHER_PROMPT);
        handler.handle(completed(PROMPT));
        Prompt.Completed own = completed(OTHER_PROMPT);
        handler.handle(own);

        assertEquals(1, handler.getCount());
        assertSame(own, handler.getLastHandledSignal());
    }

    @Test
    void theHandledSignalsAreHandedOutAsACopy() throws Exception {
        harness.start(false);
        handler.connect(harness.clientConnection(), List.of(), "/");
        Prompt.Completed first = completed(PROMPT);
        handler.handle(first);

        DBusSignal[] handled = handler.getHandled();
        handler.handle(completed(OTHER_PROMPT));

        assertSame(first, handled[0], "what a caller holds does not change under it");
        assertEquals(2, handler.getCount());
        assertEquals(2, handler.getHandledSignals(Prompt.Completed.class).size());
    }
}
