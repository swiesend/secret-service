package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.Service;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The prompts of {@link FakeSecretService}, which the other tests rely on: each is an object of its
 * own, and the prompts that unlock the collection show their dialogs as gnome-keyring does, one at a
 * time and only once the client calls {@code Prompt}.
 */
class FakePromptTest {

    private static final DBusPath COLLECTION = new DBusPath(FakeSecretService.COLLECTION_PATH);

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private Service service;
    private Prompt prompt;

    @BeforeEach
    void start() throws Exception {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
        harness.start(false);
        harness.fake().lockCollection();
        harness.fake().setRequirePromptForCollectionUnlock(true);
        service = harness.service().getService();
        // Receives every Completed signal on the bus from here on.
        prompt = new Prompt(service);
    }

    @AfterEach
    void stop() {
        if (prompt != null) prompt.getSignalHandler().disconnect();
        harness.stop();
    }

    @Test
    void eachPromptHasAPathOfItsOwn() {
        DBusPath first = unlockPrompt();
        DBusPath second = unlockPrompt();

        assertNotEquals(first, second);
    }

    @Test
    void theDialogShowsOnceThePromptIsCalled() {
        DBusPath unlock = unlockPrompt();
        assertFalse(harness.fake().hasPendingPrompt(), "no dialog before Prompt");

        assertTrue(prompt.prompt(unlock));

        assertTrue(harness.fake().hasPendingPrompt(), "its dialog shows");
        assertEquals(List.of(unlock.getPath()), harness.fake().promptCalls());
    }

    @Test
    void aDismissedPromptCompletesDismissed() throws Exception {
        DBusPath unlock = unlockPrompt();
        prompt.prompt(unlock);

        assertTrue(prompt.dismiss(unlock));

        Prompt.Completed completed = completedOn(unlock);
        assertNotNull(completed, "the provider answers a Dismiss with Completed, as the specification says");
        assertTrue(completed.dismissed);
        assertEquals(List.of(unlock.getPath()), harness.fake().dismissCalls());
        assertFalse(harness.fake().hasPendingPrompt(), "and its dialog closes");
        assertTrue(harness.fake().isCollectionLocked());
    }

    @Test
    void oneAnswerCompletesTheUnlockPromptsThatWait() throws Exception {
        DBusPath first = unlockPrompt();
        DBusPath second = unlockPrompt();
        prompt.prompt(first);
        prompt.prompt(second);

        harness.fake().approvePendingPrompt();

        assertFalse(completedOn(first).dismissed, "the user unlocked the collection in the first dialog");
        assertFalse(completedOn(second).dismissed, "and the second prompt completes without a dialog of its own");
        assertFalse(harness.fake().hasPendingPrompt());
        assertFalse(harness.fake().isCollectionLocked());
    }

    @Test
    void aRefusedDialogBringsUpTheNextOne() throws Exception {
        DBusPath first = unlockPrompt();
        DBusPath second = unlockPrompt();
        prompt.prompt(first);
        prompt.prompt(second);

        harness.fake().refusePendingPrompt();

        assertTrue(completedOn(first).dismissed, "the user cancelled the first dialog");
        assertNull(prompt.getSignalHandler().getLastHandledSignal(Prompt.Completed.class, second.getPath()),
                "the second prompt still waits");
        assertTrue(harness.fake().hasPendingPrompt(), "with a dialog of its own on the screen");

        harness.fake().approvePendingPrompt();

        assertFalse(completedOn(second).dismissed);
        assertFalse(harness.fake().isCollectionLocked());
    }

    private DBusPath unlockPrompt() {
        DBusPath path = service.unlock(List.of(COLLECTION)).orElseThrow().b;
        assertTrue(path.getPath().startsWith("/org/freedesktop/secrets/prompt/u"), path.getPath());
        return path;
    }

    /** The Completed signal for the prompt at {@code path}, waiting up to five seconds for it. */
    private Prompt.Completed completedOn(DBusPath path) throws InterruptedException {
        long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
        Prompt.Completed completed;
        while ((completed = prompt.getSignalHandler().getLastHandledSignal(Prompt.Completed.class, path.getPath())) == null
                && java.lang.System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        return completed;
    }
}
