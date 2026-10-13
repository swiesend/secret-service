package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.SearchMode;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Once the user has refused to unlock the collection, the library does not ask again. {@code search()}
 * asked once more for every item whose label or attributes it read, and {@code deleteItems()} once
 * more for every item.
 *
 * <p>Against {@link FakeSecretService}, with the collection locked and its unlock refused. Each
 * {@code Unlock} call stands for one dialog.</p>
 */
class AskOnceTest {

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

    /** Opens the fake collection, locked, with its unlock refused as if the user dismissed it. */
    private CollectionInterface startRefused() throws Exception {
        CollectionInterface collection = harness.start(false);
        fake = harness.fake();
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);
        return collection;
    }

    @Test
    void searchAsksOnceForAllItems() throws Exception {
        CollectionInterface collection = startRefused();

        assertEquals(List.of(FakeSecretService.ITEM_PATH), collection.search("fake", SearchMode.BY_NAME),
                "the items of a locked collection can still be found");
        assertEquals(1, fake.unlockCalls().size(), "one dialog, not one more per item");
    }

    @Test
    void deleteItemsAsksOnceAndDeletesNothing() throws Exception {
        CollectionInterface collection = startRefused();

        assertFalse(collection.deleteItems(List.of(FakeSecretService.ITEM_PATH)));
        assertEquals(1, fake.unlockCalls().size(), "one dialog for all the items");
        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH), "and nothing was deleted");
    }
}
