package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.System;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A D-Bus call that gets no reply in time looks like a failure to its caller, although the provider
 * can still carry it out. It came back empty without a word in the log, which left a slow provider
 * indistinguishable from a refusing one.
 *
 * <p>Against {@link de.swiesend.secretservice.FakeSecretService}, which answers SearchItems late
 * when told to.</p>
 */
class ReplyTimeoutTest {

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
    void aCallWithoutAReplyInTimeIsLogged() throws Exception {
        harness.start(false);
        harness.fake().setSearchReplyDelay(Duration.ofSeconds(3));

        PrintStream original = java.lang.System.err;   // where slf4j-simple writes
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        java.lang.System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        Optional<?> result;
        try (ServiceInterface service = SecretService.create(
                Optional.of(System.wrap(harness.clientConnection()))).orElseThrow()) {
            result = service.getService().searchItems(Map.of("uuid", "any"));
        } finally {
            java.lang.System.setErr(original);
        }

        assertTrue(result.isEmpty(), "the reply came after the wait had ended");
        assertTrue(captured.toString(StandardCharsets.UTF_8)
                        .contains("No reply to org.freedesktop.Secret.Service/SearchItems"),
                "and the log says so, rather than nothing");
    }
}
