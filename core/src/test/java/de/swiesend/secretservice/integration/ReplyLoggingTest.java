package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.handlers.MessageHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the library's most verbose log levels write about a D-Bus exchange.
 *
 * <p>A reply carries item labels, attributes and secret values, and setting an item's label sends
 * the new one. At DEBUG and TRACE the library logs the shape of the exchange -- method, parameter
 * count, signature -- and never the values: a label often describes the secret it guards, and a
 * log travels further than a keyring does.</p>
 *
 * <p>Runs only in the {@code payload-logging} surefire execution, a JVM of its own in which the
 * library's loggers are at TRACE. The default run logs at INFO, where these statements are not
 * reached at all.</p>
 */
@Tag("payload-logging")
class ReplyLoggingTest {

    private static final String NEW_LABEL = "relabelled-bank-login";

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
    void anExchangeIsLoggedByItsShapeNeverByItsValues() throws Exception {
        // At INFO the statements under test never run, and every check below would pass. Fail
        // instead, so a run outside the payload-logging execution cannot look like a pass.
        assertTrue(LoggerFactory.getLogger(MessageHandler.class).isTraceEnabled(),
                "run through the payload-logging surefire execution, which sets TRACE");

        PrintStream original = System.err;   // where slf4j-simple writes
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            CollectionInterface collection = harness.start(false);
            assertEquals(Optional.of("fake-item"), collection.getItemLabel(FakeSecretService.ITEM_PATH),
                    "the label is read through a property reply");
            collection.setItemLabel(FakeSecretService.ITEM_PATH, NEW_LABEL);
            assertEquals(FakeSecretService.SECRET_VALUE,
                    collection.withSecret(FakeSecretService.ITEM_PATH, String::new).orElseThrow(),
                    "the secret is read through a GetSecret reply");
        } finally {
            System.setErr(original);
        }
        String log = captured.toString(StandardCharsets.UTF_8);

        assertFalse(log.contains("fake-item"), "a label in a reply must not reach a log message");
        assertFalse(log.contains(NEW_LABEL), "a label being set must not reach a log message");
        assertFalse(log.contains(FakeSecretService.SECRET_VALUE), "a secret must not reach a log message");
        // Proof that the exchange was logged at all; without it the checks above pass vacuously.
        assertTrue(log.contains("Reply to"), "the replies were logged, by their shape");
    }
}
