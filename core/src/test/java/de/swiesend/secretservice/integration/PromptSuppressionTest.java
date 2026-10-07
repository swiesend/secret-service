package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code disablePrompt()} must suppress <b>every</b> dialog this collection can raise -- and
 * nothing else: an operation that needs no dialog must still happen.
 *
 * <p>Each prompt test asserts both directions: the operation completes through the prompt when
 * prompting is allowed, and is refused when it is not. Asserting only the refusal would pass
 * against an implementation that had simply broken the operation.</p>
 */
class PromptSuppressionTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private FakeSecretService fake;

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    /** Starts the fixture and opens the fake collection; keeps {@code fake} pointing at it. */
    private CollectionInterface start(boolean itemLocked) throws Exception {
        CollectionInterface collection = harness.start(itemLocked);
        fake = harness.fake();
        // Put item lock/unlock behind a prompt. Without it the fake completes them inline, and
        // these tests exercise the no-prompt path instead of the prompt branches they name.
        fake.setRequirePromptForItemOps(true);
        return collection;
    }

    @Test
    void unlockItemPromptsWhenAllowedAndRefusesWhenNot() throws Exception {
        CollectionInterface allowed = start(true);
        assertTrue(allowed.unlockItem(FakeSecretService.ITEM_PATH),
                "with prompting enabled the unlock completes through the prompt");
        stop();

        CollectionInterface suppressed = start(true);
        assertTrue(suppressed.disablePrompt());
        assertFalse(suppressed.unlockItem(FakeSecretService.ITEM_PATH),
                "with prompting disabled the item must stay locked, not be unlocked by a dialog "
                        + "the caller opted out of");
        assertTrue(fake.isItemLocked(), "the item was not unlocked behind the caller's back");
    }

    @Test
    void lockItemPromptsWhenAllowedAndRefusesWhenNot() throws Exception {
        CollectionInterface allowed = start(false);
        FakeSecretService allowedFake = fake;
        // Answer the prompt from another thread while lockItem waits for it. Poll rather than
        // sleep a fixed time: lockItem makes two D-Bus round trips before the fake has a prompt
        // outstanding, and a loaded runner can outlast any fixed sleep.
        Thread approver = new Thread(() -> {
            try {
                long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
                while (!allowedFake.hasPendingPrompt() && java.lang.System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                // Only a prompt that exists: answering after the deadline would emit a Completed
                // signal that a later await on the same bus could take as a stale answer.
                if (allowedFake.hasPendingPrompt()) {
                    allowedFake.approvePendingPrompt();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "approver");
        approver.setDaemon(true);
        approver.start();
        assertTrue(allowed.lockItem(FakeSecretService.ITEM_PATH),
                "with prompting enabled the lock completes through the prompt");
        approver.join(5_000);
        stop();

        CollectionInterface suppressed = start(false);
        assertTrue(suppressed.disablePrompt());
        // Nobody answers the prompt, so the item stays unlocked, as on a real provider when the
        // client never sends Prompt().
        assertFalse(suppressed.lockItem(FakeSecretService.ITEM_PATH),
                "with prompting disabled the item must stay unlocked");
        assertFalse(fake.isItemLocked(), "the item was not locked behind the caller's back");
    }

    @Test
    void lockingStillWorksWithoutAPromptWhenPromptingIsDisabled() throws Exception {
        // disablePrompt() suppresses dialogs, not locking. Most providers lock without any
        // prompt -- gnome-keyring answers Lock with a non-empty locked list and a "/" path -- so a
        // headless consumer that disables prompts must still be able to lock an item.
        CollectionInterface collection = start(false);
        fake.setRequirePromptForItemOps(false);   // locking needs no prompt here
        assertTrue(collection.disablePrompt());

        assertTrue(collection.lockItem(FakeSecretService.ITEM_PATH),
                "locking needs no dialog here, so disabling prompts must not prevent it");
        assertTrue(fake.isItemLocked(), "and the item really is locked");
    }

    @Test
    void aReadDoesNotPromptWhenPromptingIsDisabled() throws Exception {
        // The consequence that reaches ordinary users: on a provider that locks items, getSecret
        // goes through unlockItem, so the suppression has to hold all the way down the read path.
        CollectionInterface collection = start(true);
        assertTrue(collection.disablePrompt());

        assertTrue(collection.getSecret(FakeSecretService.ITEM_PATH).isEmpty(),
                "a locked item cannot be read without a prompt, so the read reports nothing");
        assertTrue(fake.isItemLocked(), "and no dialog unlocked it");
    }
}
