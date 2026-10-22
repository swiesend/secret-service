package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
            // The answer to an earlier prompt on the same path: the user refused that one. A
            // provider that restarts numbers its prompts from the start again.
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

    @Test
    void anInterruptedAwaitDismissesItsPrompt() throws Exception {
        harness.start(false);
        List<String> dismissed = Collections.synchronizedList(new ArrayList<>());
        Prompt prompt = recording(dismissed);
        try {
            Thread.currentThread().interrupt();
            Prompt.Completed completed = prompt.await(new DBusPath(FakeSecretService.PROMPT_PATH), Duration.ofSeconds(5));

            assertTrue(Thread.interrupted(), "the interrupt is kept for the caller");
            assertNull(completed, "nobody answered");
            assertEquals(List.of(FakeSecretService.PROMPT_PATH), dismissed,
                    "the prompt that nobody waits for any more is dismissed");
        } finally {
            Thread.interrupted();
            prompt.getSignalHandler().disconnect();
        }
    }

    @Test
    void eachAwaitDismissesItsOwnPrompt() throws Exception {
        harness.start(false);
        List<String> dismissed = Collections.synchronizedList(new ArrayList<>());
        Prompt prompt = recording(dismissed);
        String first = FakeSecretService.PROMPT_PATH + "1";
        String second = FakeSecretService.PROMPT_PATH + "2";
        try {
            // A second thread prompts through the same object while the first still waits, and
            // waits longer. Nobody answers either prompt.
            Thread other = new Thread(() -> {
                try {
                    Thread.sleep(300);
                    prompt.await(new DBusPath(second), Duration.ofSeconds(2));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, "second-await");
            other.start();

            assertNull(prompt.await(new DBusPath(first), Duration.ofSeconds(1)), "nobody answered the first");
            other.join(10_000);

            assertEquals(List.of(first, second), dismissed, "each await dismissed its own prompt, in order");
        } finally {
            prompt.getSignalHandler().disconnect();
        }
    }

    @Test
    void aTimedOutAwaitWaitsForNoAnswerToItsDismissal() throws Exception {
        // oo7 answers a Dismiss with no Completed.
        harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.OO7_DISMISS_SENDS_NO_COMPLETED);
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        DBusPath unlock = harness.service().getService()
                .unlock(List.of(new DBusPath(FakeSecretService.COLLECTION_PATH))).orElseThrow().b;
        Prompt prompt = new Prompt(harness.service().getService());
        try {
            long start = java.lang.System.nanoTime();
            assertNull(prompt.await(unlock, Duration.ofSeconds(1)), "nobody answered the dialog");
            long waited = (java.lang.System.nanoTime() - start) / 1_000_000;

            assertEquals(List.of(unlock.getPath()), fake.dismissCalls(), "the prompt was dismissed");
            assertTrue(waited < 2_500, "and the await returned at its timeout, after " + waited + " ms");
        } finally {
            prompt.getSignalHandler().disconnect();
        }
    }

    /** A Prompt that records the paths it dismisses, before it dismisses them. */
    private Prompt recording(List<String> dismissed) {
        return new Prompt(harness.service().getService()) {
            @Override
            public boolean dismiss() {
                dismissed.add(getObjectPath());
                return super.dismiss();
            }

            @Override
            public boolean dismiss(DBusPath path) {
                dismissed.add(path.getPath());
                return super.dismiss(path);
            }
        };
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
