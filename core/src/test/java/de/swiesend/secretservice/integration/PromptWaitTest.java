package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.interfaces.Prompt.Completed;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A wait for a prompt's answer takes the answer from the provider only, and ends when the provider
 * has left the bus or the connection has closed. Any client on the bus could send a Completed
 * signal for the prompt's path, and a wait that nothing could end any more lasted its whole
 * timeout, 120 seconds by default.
 *
 * <p>Against {@link FakeSecretService}, whose prompt stays open: the user answers no dialog.</p>
 */
class PromptWaitTest {

    private static final Duration LONG = Duration.ofSeconds(60);

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private final ExecutorService background = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "prompt-wait-test");
        thread.setDaemon(true);
        return thread;
    });

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        background.shutdownNow();
        harness.stop();
    }

    /** Starts the fake with a locked collection whose unlock asks the user, who does not answer. */
    private void startWithAnOpenPrompt() throws Exception {
        harness.start(false);
        harness.fake().lockCollection();
        harness.fake().setRequirePromptForCollectionUnlock(true);
        harness.fake().setLeavePromptsOpen(true);
    }

    private static DBusPath unlockPrompt(Service service) {
        return service.unlock(List.of(new DBusPath(FakeSecretService.COLLECTION_PATH))).orElseThrow().b;
    }

    private <T> Future<T> inBackground(Callable<T> task) {
        return background.submit(task);
    }

    /** Until the client has shown the prompt: the wait has begun then. */
    private void awaitShown(DBusPath prompt) throws InterruptedException {
        for (int i = 0; i < 100 && !harness.fake().promptCalls().contains(prompt.getPath()); i++) {
            Thread.sleep(50);
        }
        assertTrue(harness.fake().promptCalls().contains(prompt.getPath()), "the client showed the prompt");
    }

    @Test
    void aCompletedSignalFromAnotherClientIsNotTheAnswer() throws Exception {
        startWithAnOpenPrompt();
        DBusPath prompt = unlockPrompt(harness.rawService());
        Prompt waiting = new Prompt(harness.rawService());
        try {
            Future<Completed> answer = inBackground(() -> waiting.await(prompt, Duration.ofSeconds(3)));
            awaitShown(prompt);
            // A consent, from a client that is not the provider.
            DBusConnection other = harness.connectAnother();
            other.sendMessage(new Completed(prompt.getPath(), false, new Variant<>(new ArrayList<DBusPath>(), "ao")));

            assertNull(answer.get(20, TimeUnit.SECONDS), "only the provider answers its prompt");
        } finally {
            waiting.getSignalHandler().disconnect();
        }
    }

    @Test
    void aWaitEndsWhenTheProviderLeavesTheBus() throws Exception {
        startWithAnOpenPrompt();
        DBusPath prompt = unlockPrompt(harness.rawService());
        Prompt waiting = new Prompt(harness.rawService());
        try {
            long start = java.lang.System.nanoTime();
            Future<Completed> answer = inBackground(() -> waiting.await(prompt, LONG));
            awaitShown(prompt);
            harness.releaseProviderName();

            assertNull(answer.get(20, TimeUnit.SECONDS));
            assertTrue(java.lang.System.nanoTime() - start < Duration.ofSeconds(20).toNanos(),
                    "long before the timeout of 60 seconds");
        } finally {
            waiting.getSignalHandler().disconnect();
        }
    }

    @Test
    void aWaitEndsWhenItsConnectionCloses() throws Exception {
        startWithAnOpenPrompt();
        DBusConnection own = harness.connectAnother();
        Service service = new Service(own);
        DBusPath prompt = unlockPrompt(service);
        Prompt waiting = new Prompt(service);

        long start = java.lang.System.nanoTime();
        Future<Completed> answer = inBackground(() -> waiting.await(prompt, LONG));
        awaitShown(prompt);
        own.disconnect();

        assertNull(answer.get(20, TimeUnit.SECONDS));
        assertTrue(java.lang.System.nanoTime() - start < Duration.ofSeconds(20).toNanos(),
                "long before the timeout of 60 seconds");
    }
}
