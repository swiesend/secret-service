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
        assertTrue(allowed.lockItem(FakeSecretService.ITEM_PATH),
                "with prompting enabled the lock completes through the prompt");
        stop();

        CollectionInterface suppressed = start(false);
        assertTrue(suppressed.disablePrompt());
        assertFalse(suppressed.lockItem(FakeSecretService.ITEM_PATH),
                "with prompting disabled the item must stay unlocked");
        assertFalse(fake.isItemLocked(), "the item was not locked behind the caller's back");
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
