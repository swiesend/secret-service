package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the low-level {@link Prompt#await} answers. A prompt's result counts as the user's answer, so
 * it must be the result of that prompt and no other.
 */
class PromptResultTest {

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
    void noPromptHasNoResult() throws Exception {
        CollectionInterface collection = harness.start(true);
        // Receives every Completed signal on the bus from here on, as each Prompt does.
        Prompt prompt = new Prompt(harness.service().getService());
        try {
            harness.fake().setDismissPrompts(true);
            assertFalse(collection.unlockItem(FakeSecretService.ITEM_PATH), "the precondition: a prompt completed");
            assertTrue(received(prompt, 1), "and this handler received its Completed signal");

            assertNull(prompt.await(new DBusPath("/"), Duration.ofSeconds(1)),
                    "\"/\" names no prompt, so there is no result; the newest one belongs to another prompt");
        } finally {
            prompt.getSignalHandler().disconnect();
        }
    }

    @Test
    void anAwaitTakesOnlyTheAnswerThatArrivesWhileItWaits() throws Exception {
        harness.start(false);
        Prompt prompt = new Prompt(harness.service().getService());
        try {
            // The answer to an earlier prompt on the same path: the user refused that one. The fake
            // gives every prompt the same path; a provider that restarts reuses its paths too.
            send(FakeSecretService.PROMPT_PATH, true);
            assertTrue(received(prompt, 1), "the precondition: the earlier answer was received");

            Thread answers = new Thread(() -> {
                try {
                    Thread.sleep(300);
                    send("/org/freedesktop/secrets/prompt/other", false);   // another prompt's
                    Thread.sleep(300);
                    send(FakeSecretService.PROMPT_PATH, false);              // this prompt's
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }, "answers");
            answers.start();

            Prompt.Completed completed = prompt.await(new DBusPath(FakeSecretService.PROMPT_PATH), Duration.ofSeconds(5));
            answers.join(5_000);

            assertNotNull(completed, "this prompt was answered");
            assertFalse(completed.dismissed, "with its own answer, not with the earlier refusal");
        } finally {
            prompt.getSignalHandler().disconnect();
        }
    }

    /** Sends a {@code Completed} signal for the prompt at {@code path}, as a provider does. */
    private void send(String path, boolean dismissed) throws Exception {
        harness.clientConnection().sendMessage(
                new Prompt.Completed(path, dismissed, new Variant<>(new ArrayList<DBusPath>(), "ao")));
    }

    /** Waits up to five seconds for {@code prompt}'s handler to have received {@code count} signals. */
    static boolean received(Prompt prompt, int count) throws InterruptedException {
        long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
        while (prompt.getSignalHandler().getCount() < count && java.lang.System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        return prompt.getSignalHandler().getCount() >= count;
    }
}
