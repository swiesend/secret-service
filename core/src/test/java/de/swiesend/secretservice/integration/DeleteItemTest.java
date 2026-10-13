package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A provider answers {@code Item.Delete} with {@code "/"} when it deleted the item without a
 * prompt. The library took that answer as success only on gnome-keyring, so {@code deleteItem}
 * returned {@code false} on any other provider that gives it, after the item was gone.
 *
 * <p>Against {@link FakeSecretService}, which answers {@code "/"} without being gnome-keyring: it
 * does not own {@code org.gnome.keyring}. gnome-keyring itself, the provider in CI, cannot show the
 * difference.</p>
 */
class DeleteItemTest {

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
    void aDeletionWithoutAPromptIsReportedAsDone() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();

        assertTrue(collection.deleteItem(FakeSecretService.ITEM_PATH),
                "the provider deleted the item without a prompt, so the call succeeded");
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH), "and the item is gone");
    }

    @Test
    void nothingIsDeletedFromACollectionThatStayedLocked() throws Exception {
        // As when the user dismisses the unlock dialog. KWallet then answers Delete with "/" as
        // well, and deletes nothing, so "/" alone cannot be taken as done.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);

        assertFalse(collection.deleteItem(FakeSecretService.ITEM_PATH),
                "the collection stayed locked, so no deletion may be reported");
        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH), "and none was attempted");
    }
}
