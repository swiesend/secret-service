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
 * {@code disablePrompt()} must suppress <b>every</b> dialog this collection can raise.
 *
 * <p>It was honoured in exactly one place, {@code performPrompt}. {@code lockItem} and
 * {@code unlockItem} call {@code Prompt.await} directly, and {@code Prompt.await} on a real prompt
 * path sends the D-Bus {@code Prompt()} method, which raises the dialog. So a caller who had
 * explicitly opted out still got one — and, on a provider that locks items individually, got it on
 * an ordinary read, because {@code getSecret} reaches {@code unlockItem}.</p>
 *
 * <p>Each test asserts both directions. Asserting only the suppressed case would pass against an
 * implementation that had simply broken the operation.</p>
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
        // Put item lock/unlock behind a prompt. Without this the fake completes them inline and
        // the prompt branches are never reached -- these tests then pass by exercising the
        // no-prompt path instead of the one they name. That is what happened when the shared
        // harness was extracted and this line was left behind.
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
        // Answer the prompt from another thread while lockItem is blocked awaiting it. The fake
        // applies the lock only on approval, so this is the difference under test rather than a
        // timer that would have fired either way.
        Thread approver = new Thread(() -> {
            try {
                Thread.sleep(200);
                allowedFake.approvePendingPrompt();
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
        // Nobody answers the prompt, so the provider never locks it -- exactly what a real
        // provider does when the client never sends Prompt().
        assertFalse(suppressed.lockItem(FakeSecretService.ITEM_PATH),
                "with prompting disabled the item must stay unlocked");
        assertFalse(fake.isItemLocked(), "the item was not locked behind the caller's back");
    }

    @Test
    void lockingStillWorksWithoutAPromptWhenPromptingIsDisabled() throws Exception {
        // disablePrompt() suppresses DIALOGS, not locking. Most providers lock without any prompt
        // at all -- gnome-keyring answers Lock immediately with a non-empty locked list and a "/"
        // path -- so a headless consumer that calls disablePrompt() at startup must still be able
        // to lock an item.
        //
        // An earlier version checked isPrompting BEFORE issuing Lock and returned false, so such a
        // consumer silently could not lock anything. The other tests here cannot see it: they set
        // setRequirePromptForItemOps(true), which puts every lock behind a prompt, so the
        // no-prompt path -- the common one -- went untested.
        CollectionInterface collection = start(false);            // item starts unlocked
        fake.setRequirePromptForItemOps(false);                  // and locking needs no prompt
        assertTrue(collection.disablePrompt());

        assertTrue(collection.lockItem(FakeSecretService.ITEM_PATH),
                "locking needs no dialog here, so disabling prompts must not prevent it");
        assertTrue(fake.isItemLocked(), "and the item really is locked");
    }

    @Test
    void aReadDoesNotPromptWhenPromptingIsDisabled() throws Exception {
        // The consequence that reaches ordinary users: getSecret goes through unlockItem on a
        // provider that locks items, so the suppression has to hold all the way down.
        //
        // Not a discrimination test for this change: #73 already guarded the read path inside
        // unlockItemIfLocked, and this commit moves that guard into unlockItem so direct callers
        // get it too. What this pins is that moving it did not open the read path back up -- which
        // is the risk of relocating a check rather than adding one.
        CollectionInterface collection = start(true);
        assertTrue(collection.disablePrompt());

        assertTrue(collection.getSecret(FakeSecretService.ITEM_PATH).isEmpty(),
                "a locked item cannot be read without a prompt, so the read reports nothing");
        assertTrue(fake.isItemLocked(), "and no dialog unlocked it");
    }
}
