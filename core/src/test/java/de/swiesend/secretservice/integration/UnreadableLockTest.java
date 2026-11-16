package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Item;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A {@code Locked} property that cannot be read does not say "unlocked". The low-level
 * {@code isLocked()} answers {@code false} for it, and the functional {@code Collection} acted on
 * that: it took the user's permission as given, created and deleted items, and read and changed an
 * item, where the provider had not said that the collection or the item was unlocked.
 *
 * <p>Against {@link FakeSecretService}, whose collection and item stay unlocked while their
 * {@code Locked} property answers with an error. So every call would succeed if it were made, and
 * what the library refuses, it refuses for the answer that it did not get.</p>
 */
class UnreadableLockTest {

    private static final String ITEM = FakeSecretService.ITEM_PATH;

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private CollectionInterface collection;
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

    /** An unlocked collection that does not say so. */
    private void startWithAnUnreadableCollection() throws Exception {
        collection = harness.start(false);
        fake = harness.fake();
        fake.setCollectionLockUnreadable(true);
        // As KeePassXC: Lock answers with a prompt, which a consent cycle does not carry out. The
        // collection so stays unlocked, and no wait for a lock that cannot be read holds up the test.
        fake.setRequirePromptForCollectionLock(true);
    }

    /** Unlocked items that do not say so, in a collection that does. */
    private void startWithUnreadableItems() throws Exception {
        collection = harness.start(false);
        fake = harness.fake();
        fake.setItemLockUnreadable(true);
    }

    @Test
    void aCollectionThatDoesNotSayIsReportedAsLocked() throws Exception {
        startWithAnUnreadableCollection();

        assertTrue(collection.isLocked());
        assertFalse(fake.isCollectionLocked(), "which the provider's collection is not");
    }

    @Test
    void noItemIsCreatedInACollectionThatDoesNotSay() throws Exception {
        startWithAnUnreadableCollection();

        assertEquals(Optional.empty(), collection.createItem("label", "secret"));
        assertEquals(List.of(), fake.createItemCalls(), "CreateItem was not called");
    }

    @Test
    void theUsersPermissionIsNotTakenAsGivenForACollectionThatDoesNotSay() throws Exception {
        startWithAnUnreadableCollection();

        assertFalse(collection.unlockWithUserPermission());
        assertEquals(Optional.empty(), collection.getSecrets().map(Map::keySet),
                "and no secret is read on it");
    }

    @Test
    void aCollectionThatDoesNotSayIsNotLockedToAskForTheUsersPermission() throws Exception {
        // Without the prompt that startWithAnUnreadableCollection() puts before the lock: a Lock
        // call would lock this collection, and nothing would show the client that it had.
        collection = harness.start(false);
        fake = harness.fake();
        fake.setCollectionLockUnreadable(true);

        assertFalse(collection.unlockWithUserPermission());
        assertEquals(Optional.empty(), collection.getSecrets().map(Map::keySet));
        assertFalse(collection.deleteItem(ITEM));

        assertEquals(List.of(), fake.lockCalls(), "no Lock was sent");
        assertFalse(fake.isCollectionLocked(), "and the collection is not left locked");
    }

    @Test
    void aCollectionThatStopsSayingAfterItsLockCallIsAskedToUnlock() throws Exception {
        collection = harness.start(false);
        fake = harness.fake();
        fake.setCollectionLockUnreadableOnceLocked(true);

        assertFalse(collection.unlockWithUserPermission(), "nothing says that it is unlocked");

        assertEquals(List.of(FakeSecretService.COLLECTION_PATH), fake.lockCalls());
        assertTrue(fake.unlockCalls().contains(FakeSecretService.COLLECTION_PATH), "Unlock was sent");
        assertFalse(fake.isCollectionLocked(), "and the collection is not left locked");
    }

    @Test
    void aLockedPropertyOfAnotherTypeIsNoAnswer() throws Exception {
        collection = harness.start(false);
        fake = harness.fake();
        fake.setLockedAnswersWithText(true);
        Item item = new Item(new DBusPath(ITEM), harness.service().getService());
        de.swiesend.secretservice.Collection lowLevel = new de.swiesend.secretservice.Collection(
                new DBusPath(FakeSecretService.COLLECTION_PATH), harness.service().getService().getConnection());

        assertEquals(Optional.empty(), item.lockedState());
        assertFalse(item.isLocked());
        assertEquals(Optional.empty(), lowLevel.lockedState());
        assertFalse(lowLevel.isLocked());

        assertTrue(collection.isLocked(), "as a collection that does not say");
        assertFalse(collection.unlockItem(ITEM));
        assertEquals(Optional.empty(), collection.getSecret(ITEM).map(String::new));
    }

    @Test
    void noItemIsDeletedFromACollectionThatDoesNotSay() throws Exception {
        startWithAnUnreadableCollection();

        assertFalse(collection.deleteItem(ITEM));
        assertFalse(collection.deleteItems(List.of(ITEM)));
        assertTrue(fake.hasItem(ITEM), "the item is kept");
    }

    @Test
    void theSecretOfAnItemThatDoesNotSayIsNotRead() throws Exception {
        startWithUnreadableItems();

        assertEquals(Optional.empty(), collection.getSecret(ITEM).map(String::new));
        assertEquals(Optional.empty(), collection.withSecret(ITEM, secret -> "read"));
    }

    @Test
    void anItemThatDoesNotSayIsNotReportedAsUnlocked() throws Exception {
        startWithUnreadableItems();

        assertFalse(collection.unlockItem(ITEM));
        assertEquals(List.of(), fake.unlockCalls(), "and no Unlock is sent for it");
    }

    @Test
    void anItemThatDoesNotSayIsNotChanged() throws Exception {
        startWithUnreadableItems();

        assertFalse(collection.setItemLabel(ITEM, "renamed"));
        assertFalse(collection.updateItem(ITEM, "renamed", "overwritten", Map.of("k", "v")));
        assertEquals(List.of(), fake.itemPropertySets(), "no property was set");
        assertEquals(0, fake.setSecretCalls(), "and no secret");
    }

    @Test
    void theBulkReadLeavesOutAnItemThatDoesNotSay() throws Exception {
        startWithUnreadableItems();

        assertEquals(Optional.of(List.of()), collection.withSecrets(secrets -> List.copyOf(secrets.keySet())));
        assertFalse(fake.unlockRequests().stream().anyMatch(paths -> paths.contains(ITEM)),
                "and sends no Unlock for it");
    }

    @Test
    void theBulkReadWarnsThatItLeftItemsOut() throws Exception {
        startWithUnreadableItems();

        PrintStream original = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        // slf4j-simple writes to System.err.
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            assertEquals(Optional.of(0), collection.withSecrets(Map::size));
        } finally {
            System.setErr(original);
        }

        String warnings = captured.toString(StandardCharsets.UTF_8).lines()
                .filter(line -> line.contains("WARN")).reduce("", (all, line) -> all + line + "\n");
        assertTrue(warnings.contains("1 of 1 items do not say whether they are locked"), warnings);
        assertFalse(warnings.contains(ITEM), "without the item's path");
    }

    @Test
    void theLowLevelItemTellsALockThatCannotBeReadFromAnUnlockedItem() throws Exception {
        startWithUnreadableItems();
        Item item = new Item(new DBusPath(ITEM), harness.service().getService());

        assertEquals(Optional.empty(), item.lockedState());
        assertFalse(item.isLocked(), "which isLocked() reports as unlocked");

        fake.setItemLockUnreadable(false);
        assertEquals(Optional.of(false), item.lockedState());
    }
}
