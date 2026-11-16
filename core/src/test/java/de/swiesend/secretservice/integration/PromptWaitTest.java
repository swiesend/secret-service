package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.interfaces.Prompt.Completed;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A wait for a prompt's answer ends when the provider has left the bus or the connection has
 * closed. Nothing could answer any more, and the wait still lasted its whole timeout, 120 seconds
 * by default.
 *
 * <p>Against {@link FakeSecretService}, whose unlock prompt stays open until a test answers it: the
 * user answers no dialog.</p>
 */
class PromptWaitTest {

    private static final Duration LONG = Duration.ofSeconds(60);
    private static final Duration SOON = Duration.ofSeconds(20);

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
    private CollectionInterface startWithAnOpenPrompt(boolean asGnomeKeyring) throws Exception {
        CollectionInterface collection = asGnomeKeyring ? harness.startAsGnomeKeyring(false) : harness.start(false);
        harness.fake().lockCollection();
        harness.fake().setRequirePromptForCollectionUnlock(true);
        return collection;
    }

    private static DBusPath unlockPrompt(Service service) {
        return service.unlock(List.of(new DBusPath(FakeSecretService.COLLECTION_PATH))).orElseThrow().b;
    }

    private <T> Future<T> inBackground(Callable<T> task) {
        return background.submit(task);
    }

    /** Until the client has shown a prompt: the wait has begun then. */
    private void awaitShown() throws InterruptedException {
        for (int i = 0; i < 100 && harness.fake().promptCalls().isEmpty(); i++) {
            Thread.sleep(50);
        }
        assertFalse(harness.fake().promptCalls().isEmpty(), "the client showed the prompt");
    }

    private static void assertEndedSoon(long start) {
        assertTrue(java.lang.System.nanoTime() - start < SOON.toNanos(), "long before the timeout of 60 seconds");
    }

    @Test
    void aWaitEndsWhenTheProviderLeavesTheBus() throws Exception {
        startWithAnOpenPrompt(false);
        Service service = harness.service().getService();
        DBusPath prompt = unlockPrompt(service);
        Prompt waiting = new Prompt(service);
        try {
            long start = java.lang.System.nanoTime();
            Future<Completed> answer = inBackground(() -> waiting.await(prompt, LONG));
            awaitShown();
            harness.releaseProviderName();

            assertNull(answer.get(SOON.toSeconds(), TimeUnit.SECONDS));
            assertEndedSoon(start);
            assertEquals(List.of(), harness.fake().dismissCalls(), "there is no prompt left to dismiss");
        } finally {
            waiting.getSignalHandler().disconnect();
        }
    }

    @Test
    void aWaitEndsWhenItsConnectionCloses() throws Exception {
        startWithAnOpenPrompt(false);
        DBusConnection own = harness.connectAnother();
        Service service = new Service(own);
        DBusPath prompt = unlockPrompt(service);
        Prompt waiting = new Prompt(service);

        long start = java.lang.System.nanoTime();
        Future<Completed> answer = inBackground(() -> waiting.await(prompt, LONG));
        awaitShown();
        own.disconnect();

        assertNull(answer.get(SOON.toSeconds(), TimeUnit.SECONDS));
        assertEndedSoon(start);
    }

    @Test
    void aWaitOnGnomeKeyringsUnlockDialogEndsWhenItLeavesTheBus() throws Exception {
        // Through the registry of gnome-keyring's open unlock prompts, which waits for itself.
        CollectionInterface collection = startWithAnOpenPrompt(true);
        harness.service().setTimeout(LONG);

        long start = java.lang.System.nanoTime();
        Future<Boolean> unlocked = inBackground(() -> collection.getSecret(FakeSecretService.ITEM_PATH).isPresent());
        awaitShown();
        harness.releaseProviderName();

        assertFalse(unlocked.get(SOON.toSeconds(), TimeUnit.SECONDS));
        assertEndedSoon(start);
    }
}
