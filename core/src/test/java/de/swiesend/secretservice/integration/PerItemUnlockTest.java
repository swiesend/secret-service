package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Issue #45: a provider may lock items <b>individually</b>, and the client must then unlock the item
 * before reading it. The library only unlocked the collection, so on KeePassXC a read of a locked
 * item failed.
 *
 * <p>No provider in CI reproduces this. gnome-keyring never locks a single item, and the KeePassXC
 * container sets {@code ConfirmAccessItem=false}, which switches the behaviour off. These tests
 * therefore run against {@link FakeSecretService} on a private session bus: a provider that locks
 * one item and clears it only when {@code Unlock} names that item's own path.</p>
 *
 * <p>The suite skips when {@code dbus-daemon} is not on the PATH.</p>
 */
class PerItemUnlockTest {

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
    void aLockedItemIsUnlockedAutomaticallyAndThenRead() throws Exception {
        CollectionInterface collection = start(true);

        Optional<char[]> secret = collection.getSecret(FakeSecretService.ITEM_PATH);

        assertTrue(secret.isPresent(), "a locked item must be unlocked and then read");
        assertEquals(FakeSecretService.SECRET_VALUE, new String(secret.get()));
        assertTrue(fake.unlockCalls().contains(FakeSecretService.ITEM_PATH),
                "the ITEM's own path must be unlocked; unlock calls were " + fake.unlockCalls());
        assertFalse(fake.isItemLocked(), "the item is unlocked afterwards");
    }

    @Test
    void unlockingTheCollectionAloneDoesNotReachTheItem() throws Exception {
        // The discrimination test. Before the fix the client unlocked only the collection, which
        // this fake deliberately treats as a no-op for the item -- exactly as KeePassXC does -- so
        // the read fell through to GetSecret on a locked item and failed.
        CollectionInterface collection = start(true);

        assertTrue(collection.unlockWithUserPermission(), "the collection unlocks as before");
        assertTrue(fake.isItemLocked(),
                "precondition: a collection-level unlock must leave the item locked");

        assertTrue(collection.getSecret(FakeSecretService.ITEM_PATH).isPresent(),
                "the read must still succeed, which is only possible if the ITEM was unlocked too");
    }

    @Test
    void aDismissedPromptReturnsEmptyRatherThanFailingLater() throws Exception {
        // NOT a discrimination test: without the fix the read also comes back empty, because
        // GetSecret on a locked item fails anyway. What this pins is the *manner* of the failure --
        // an empty Optional rather than an exception or a hang -- and that a refusal leaves the item
        // locked instead of being reported as an unreadable secret.
        CollectionInterface collection = start(true);
        fake.setDismissPrompts(true);

        Optional<char[]> secret = collection.getSecret(FakeSecretService.ITEM_PATH);

        assertTrue(secret.isEmpty(), "a refused unlock must report no secret, not throw or hang");
        assertTrue(fake.isItemLocked(), "the item stays locked when the user refuses");
    }

    @Test
    void aLockedCollectionDoesNotTriggerASecondUnlockOfTheItem() throws Exception {
        // The regression that shipped in #72. gnome-keyring reports EVERY item as locked while its
        // collection is locked -- confirmed against a live daemon -- so "the item is locked" alone
        // is not the per-item condition. When the collection-level unlock has failed (the user
        // dismissed the prompt, the stored password is wrong, disablePrompt() is set), asking for a
        // per-item unlock raises a SECOND prompt for the keyring they just refused.
        //
        // Collection unlocked but item locked is the genuine per-item case, and the only one the
        // library may act on.
        // the item itself is not individually locked
        CollectionInterface collection = start(false);
        fake.lockCollection();                 // ...but the collection is, so the item reports locked
        fake.setRefuseCollectionUnlock(true);  // and the collection unlock fails, as when refused
        fake.setDismissPrompts(true);

        assertTrue(collection.getSecret(FakeSecretService.ITEM_PATH).isEmpty(),
                "a locked collection yields no secret");
        assertTrue(fake.unlockCalls().stream().noneMatch(FakeSecretService.ITEM_PATH::equals),
                "no item-level unlock may be attempted while the collection is locked; "
                        + "unlock calls were " + fake.unlockCalls());
    }

    @Test
    void anUnlockedItemIsNeverUnlockedAgain() throws Exception {
        // NOT a discrimination test either -- it passes before the fix, trivially, because the code
        // it guards did not exist. That is precisely its job: it is the regression guard for
        // existing consumers such as Cryptomator on gnome-keyring, where items are never locked
        // individually. The new path must not run at all: no extra D-Bus call, and no prompt that
        // did not appear before.
        CollectionInterface collection = start(false);

        Optional<char[]> secret = collection.getSecret(FakeSecretService.ITEM_PATH);

        assertTrue(secret.isPresent(), "an unlocked item reads as it always did");
        assertEquals(FakeSecretService.SECRET_VALUE, new String(secret.get()));
        assertTrue(fake.unlockCalls().stream().noneMatch(FakeSecretService.ITEM_PATH::equals),
                "no item-level unlock may be attempted; unlock calls were " + fake.unlockCalls());
    }
}
