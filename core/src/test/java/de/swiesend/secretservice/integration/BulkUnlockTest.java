package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static de.swiesend.secretservice.FakeSecretService.ITEM_PATH;
import static de.swiesend.secretservice.FakeSecretService.SECOND_ITEM_PATH;
import static de.swiesend.secretservice.FakeSecretService.SECOND_SECRET_VALUE;
import static de.swiesend.secretservice.FakeSecretService.SECRET_VALUE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KeePassXC keeps an item locked for a client until the user confirms that client's access, which
 * it asks by default, and shows one dialog for all the items of one {@code Unlock} call.
 * {@code getSecrets()} and {@code withSecrets()} skipped every such item, so a client that the user
 * had not allowed yet read nothing. They unlock the locked items together now, through one prompt.
 *
 * <p>Against {@link FakeSecretService} with two items, each locked on its own.</p>
 */
class BulkUnlockTest {

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

    private CollectionInterface twoLockedItems() throws Exception {
        CollectionInterface collection = harness.start(true);
        harness.fake().addSecondItem(true);
        return collection;
    }

    /** The {@code Unlock} calls for items: the bulk read also unlocks the collection first. */
    private List<List<String>> itemUnlocks() {
        return harness.fake().unlockRequests().stream()
                .filter(paths -> !paths.contains(FakeSecretService.COLLECTION_PATH))
                .toList();
    }

    private static Map<String, String> strings(Map<String, char[]> secrets) {
        Map<String, String> copy = new TreeMap<>();
        secrets.forEach((path, secret) -> copy.put(path, new String(secret)));
        return copy;
    }

    @Test
    void lockedItemsAreUnlockedThroughOnePrompt() throws Exception {
        CollectionInterface collection = twoLockedItems();
        harness.fake().setRequirePromptForItemOps(true);

        assertEquals(Map.of(ITEM_PATH, SECRET_VALUE, SECOND_ITEM_PATH, SECOND_SECRET_VALUE),
                collection.withSecrets(BulkUnlockTest::strings).orElseThrow());
        assertEquals(List.of(List.of(ITEM_PATH, SECOND_ITEM_PATH)), itemUnlocks(), "one Unlock call for both");
        assertEquals(1, harness.fake().itemUnlockPrompts(), "and one prompt");
    }

    @Test
    void thePromptRunsAlsoWhenSomeItemsCameBackUnlocked() throws Exception {
        // The specification: the prompt unlocks the remaining objects. The first item comes back
        // unlocked at once, the second only through the prompt.
        CollectionInterface collection = twoLockedItems();
        harness.fake().setUnlockFirstItemWithoutPrompt(true);

        assertEquals(Map.of(ITEM_PATH, SECRET_VALUE, SECOND_ITEM_PATH, SECOND_SECRET_VALUE),
                collection.withSecrets(BulkUnlockTest::strings).orElseThrow());
        assertEquals(1, harness.fake().itemUnlockPrompts());
    }

    @Test
    void onlyTheLockedItemsAreUnlocked() throws Exception {
        CollectionInterface collection = harness.start(false);
        harness.fake().addSecondItem(true);
        harness.fake().setRequirePromptForItemOps(true);

        assertEquals(Map.of(ITEM_PATH, SECRET_VALUE, SECOND_ITEM_PATH, SECOND_SECRET_VALUE),
                collection.withSecrets(BulkUnlockTest::strings).orElseThrow());
        assertEquals(List.of(List.of(SECOND_ITEM_PATH)), itemUnlocks());
    }

    @Test
    void itemsThatStayLockedAreLeftOut() throws Exception {
        // The user dismisses the dialog.
        CollectionInterface collection = twoLockedItems();
        harness.fake().setDismissPrompts(true);
        harness.fake().reproduce(ProviderBug.KWALLET_READS_A_LOCKED_ITEM_AS_EMPTY);

        assertEquals(Map.of(), collection.withSecrets(BulkUnlockTest::strings).orElseThrow());
        assertEquals(1, itemUnlocks().size(), "asked once");
        assertEquals(0, harness.fake().lockedItemReads(), "and no locked item was read");
    }

    @Test
    void withPromptingDisabledNoItemIsUnlocked() throws Exception {
        // Unlocking a locked item needs a prompt. A first read, whose dialog the user dismisses,
        // unlocks the collection with the user's permission, so that the second gets to the items.
        CollectionInterface collection = twoLockedItems();
        harness.fake().setDismissPrompts(true);
        assertEquals(Map.of(), collection.withSecrets(BulkUnlockTest::strings).orElseThrow());
        assertTrue(collection.disablePrompt());

        assertEquals(Map.of(), collection.withSecrets(BulkUnlockTest::strings).orElseThrow());
        assertEquals(1, itemUnlocks().size(), "the first read's Unlock only");
    }
}
