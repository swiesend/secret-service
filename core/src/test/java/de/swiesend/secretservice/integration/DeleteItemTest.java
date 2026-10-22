package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

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
        fake.reproduce(ProviderBug.KWALLET_ANSWERS_DELETE_OF_A_LOCKED_ITEM_AS_DONE);
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);

        assertFalse(collection.deleteItem(FakeSecretService.ITEM_PATH),
                "the collection stayed locked, so no deletion may be reported");
        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH), "and none was attempted");
    }

    // oo7 deletes every item whose attributes include the deleted item's. The fake, which owns no
    // name of a provider that the library knows, does so on request; its items have no attributes,
    // so each has the other's.

    @Test
    void anItemIsNotDeletedWhereTheProviderWouldTakeAnotherOneAlong() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.addSecondItem(false);
        fake.reproduce(ProviderBug.OO7_DELETE_REMOVES_EVERY_ITEM_WITH_THE_ATTRIBUTES);

        assertFalse(collection.deleteItem(FakeSecretService.ITEM_PATH));
        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH));
        assertTrue(fake.hasItem(FakeSecretService.SECOND_ITEM_PATH), "the other item is kept");
    }

    @Test
    void anItemThatNoOtherOneSharesItsAttributesWithIsDeleted() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.OO7_DELETE_REMOVES_EVERY_ITEM_WITH_THE_ATTRIBUTES);

        assertTrue(collection.deleteItem(FakeSecretService.ITEM_PATH));
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
    }

    @Test
    void itemsThatShareTheirAttributesAreDeletedTogether() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.addSecondItem(false);
        fake.reproduce(ProviderBug.OO7_DELETE_REMOVES_EVERY_ITEM_WITH_THE_ATTRIBUTES);

        assertTrue(collection.deleteItems(List.of(FakeSecretService.ITEM_PATH, FakeSecretService.SECOND_ITEM_PATH)),
                "the second went with the first, and both were to be deleted");
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
        assertFalse(fake.hasItem(FakeSecretService.SECOND_ITEM_PATH));
    }

    @Test
    void anItemIsDeletedByItsPathOnAProviderThatDeletesSo() throws Exception {
        // KWallet's name: a provider that deletes the item at the path, whatever its attributes.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.requestBusName("org.kde.kwalletd5");
        fake.addSecondItem(false);

        assertTrue(collection.deleteItem(FakeSecretService.ITEM_PATH));
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
        assertTrue(fake.hasItem(FakeSecretService.SECOND_ITEM_PATH));
    }
}
