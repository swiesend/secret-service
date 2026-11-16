package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A collection takes an item's path only for an item of its own. Handed the path of an item of
 * another collection, it refuses, and sends the provider nothing: no read, no change, no deletion,
 * and no lock or unlock that would bring up a dialog first.
 *
 * <p>Against {@link FakeSecretService}, whose item of another collection answers every call as
 * done and records it. What did not reach the provider is the proof: a refusal that is only a
 * return value would pass a test of the return values alone.</p>
 */
class ItemPathScopeTest {

    private static final String OWN = FakeSecretService.ITEM_PATH;
    private static final String FOREIGN = FakeSecretService.FOREIGN_ITEM_PATH;

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

    private void start() throws Exception {
        collection = harness.start(false);
        fake = harness.fake();
        fake.addForeignItem();
    }

    /** Neither the item of the other collection was called, nor the service for it or for a dialog. */
    private void assertNothingReachedTheProvider() {
        assertEquals(List.of(), fake.foreignItemCalls(), "no call reached the other collection's item");
        assertEquals(List.of(), fake.lockCalls(), "nothing was locked");
        assertEquals(List.of(), fake.unlockCalls(), "nothing was unlocked");
        assertEquals(List.of(), fake.promptCalls(), "no prompt was shown");
    }

    @Test
    void theSecretOfAnotherCollectionsItemIsNotRead() throws Exception {
        start();

        assertEquals(Optional.empty(), collection.getSecret(FOREIGN));
        assertEquals(Optional.empty(), collection.withSecret(FOREIGN, secret -> "read"),
                "the callback is not called");
        assertNothingReachedTheProvider();
    }

    @Test
    void theLabelAndTheAttributesOfAnotherCollectionsItemAreNotRead() throws Exception {
        start();

        assertEquals(Optional.empty(), collection.getItemLabel(FOREIGN));
        assertEquals(Optional.empty(), collection.getAttributes(FOREIGN));
        assertNothingReachedTheProvider();
    }

    @Test
    void anotherCollectionsItemIsNotChanged() throws Exception {
        start();

        assertFalse(collection.setItemLabel(FOREIGN, "taken over"));
        assertFalse(collection.updateItem(FOREIGN, "taken over", "overwritten", Map.of("owner", "this")));
        assertNothingReachedTheProvider();
    }

    @Test
    void anotherCollectionsItemIsNeitherLockedNorUnlocked() throws Exception {
        start();

        assertFalse(collection.lockItem(FOREIGN));
        assertFalse(collection.unlockItem(FOREIGN));
        assertNothingReachedTheProvider();
    }

    @Test
    void anotherCollectionsItemIsNotDeletedAndTheUserIsNotAskedFirst() throws Exception {
        start();

        assertFalse(collection.deleteItem(FOREIGN));
        // The lock that precedes the unlock dialog is the first thing a deletion sends.
        assertNothingReachedTheProvider();
    }

    @Test
    void aListThatNamesAnotherCollectionsItemDeletesNothing() throws Exception {
        start();

        assertFalse(collection.deleteItems(List.of(OWN, FOREIGN)),
                "one item of another collection refuses the whole list");
        assertNothingReachedTheProvider();
        assertTrue(fake.hasItem(OWN), "all or nothing: the collection's own item is kept");
    }

    @Test
    void aRefusedPathIsNotWrittenToTheLog() throws Exception {
        // The path is the caller's text, and unchecked. One of another collection's item names
        // that collection, on gnome-keyring by its label, and one with a line break starts a
        // line of its own in the log.
        start();
        String log = logOf(() -> {
            assertEquals(Optional.empty(), collection.getSecret(FOREIGN));
            assertFalse(collection.deleteItem(FOREIGN + "\nWARN a line of the caller's"));
        });

        assertTrue(log.contains("Refusing to delete"), "the refusal is logged");
        assertFalse(log.contains("collection/other"), "without the path of the other collection's item");
        assertFalse(log.contains("a line of the caller's"), "and without the caller's text");
    }

    @Test
    void theCollectionsOwnItemIsReadChangedAndDeleted() throws Exception {
        // The counterpart: the refusals above are the path's, not the fixture's.
        start();

        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), collection.getSecret(OWN).orElseThrow());
        assertEquals(Optional.of("fake-item"), collection.getItemLabel(OWN));
        assertTrue(collection.setItemLabel(OWN, "renamed"));
        assertTrue(collection.deleteItems(List.of(OWN)));
        assertFalse(fake.hasItem(OWN));
    }

    @Test
    void theDefaultCollectionKeepsItsItemsAndRefusesTheOthers() throws Exception {
        // openDefault() opens the collection at the path that the alias names, below which its
        // items are: the paths that a search of the default collection returns.
        start();
        fake.setDefaultAlias(FakeSecretService.COLLECTION_PATH);
        SessionInterface session = harness.service().openSession().orElseThrow();

        try (CollectionInterface byAlias = session.defaultCollection().orElseThrow()) {
            assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), byAlias.getSecret(OWN).orElseThrow());
            assertEquals(Optional.empty(), byAlias.getSecret(FOREIGN));
            assertEquals(List.of(), fake.foreignItemCalls());
        }
    }

    @Test
    void aDefaultCollectionAtTheAliassPathTakesTheItemsThatTheProviderListsForIt() throws Exception {
        // Where the alias cannot be read, the collection is opened at the alias's own path, and
        // its items are below another: no prefix tells them from another collection's, and the
        // provider's list of the collection's items does.
        start();
        fake.serveCollectionAtTheDefaultAlias();
        fake.setRefuseReadAlias(true);
        SessionInterface session = harness.service().openSession().orElseThrow();

        try (CollectionInterface byAlias = session.defaultCollection().orElseThrow()) {
            assertEquals(Optional.of("fake-item"), byAlias.getItemLabel(OWN));
            assertEquals(Optional.empty(), byAlias.getSecret(FOREIGN));
            assertFalse(byAlias.deleteItem(FOREIGN));
            assertNothingReachedTheProvider();
        }
    }

    @Test
    void aDefaultCollectionAtTheAliassPathTakesNoItemWhereItsItemsCannotBeListed() throws Exception {
        // The fake serves no collection at the alias's path: nothing says whose an item is.
        start();
        fake.setRefuseReadAlias(true);
        SessionInterface session = harness.service().openSession().orElseThrow();

        try (CollectionInterface byAlias = session.defaultCollection().orElseThrow()) {
            assertEquals(Optional.empty(), byAlias.getSecret(FOREIGN));
            assertEquals(Optional.empty(), byAlias.getSecret(OWN));
            assertNothingReachedTheProvider();
        }
    }

    @Test
    void anItemNamedThroughAnAliasOfTheCollectionIsItsOwn() throws Exception {
        // The specification serves a collection at its aliases' paths too. The item is asked for
        // at the path below the collection's own, which is the one that was judged.
        start();
        fake.setDefaultAlias(FakeSecretService.COLLECTION_PATH);
        String throughTheAlias = FakeSecretService.DEFAULT_ALIAS_PATH + "/1";

        assertEquals(Optional.of("fake-item"), collection.getItemLabel(throughTheAlias));
        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), collection.getSecret(throughTheAlias).orElseThrow());
        assertTrue(collection.deleteItems(List.of(throughTheAlias)));
        assertFalse(fake.hasItem(OWN));
    }

    @Test
    void anItemNamedThroughAnAliasOfAnotherCollectionIsRefused() throws Exception {
        start();
        fake.setDefaultAlias("/org/freedesktop/secrets/collection/other");
        String throughTheAlias = FakeSecretService.DEFAULT_ALIAS_PATH + "/1";

        assertEquals(Optional.empty(), collection.getSecret(throughTheAlias));
        assertFalse(collection.deleteItem(throughTheAlias));
        assertNothingReachedTheProvider();
        assertTrue(fake.hasItem(OWN), "the item with the same id in this collection is kept");
    }

    @Test
    void aPathThatIsNoObjectPathIsRefused() throws Exception {
        start();
        fake.setDefaultAlias(FakeSecretService.COLLECTION_PATH);

        for (String path : List.of(OWN + "/", OWN + "/../1", OWN + "\n", FakeSecretService.COLLECTION_PATH + "/",
                FakeSecretService.COLLECTION_PATH + "//1", FakeSecretService.DEFAULT_ALIAS_PATH + "/1/",
                FakeSecretService.DEFAULT_ALIAS_PATH, "/org/freedesktop/secrets/aliases/de fault/1")) {
            String log = logOf(() -> {
                assertEquals(Optional.empty(), collection.getSecret(path), path);
                assertFalse(collection.deleteItem(path), path);
            });
            // Refused here, as no item of the collection, before anything is made of the path.
            assertTrue(log.contains("Refusing to read the secret"), path);
            assertTrue(log.contains("Refusing to delete"), path);
        }
        assertNothingReachedTheProvider();
        assertTrue(fake.hasItem(OWN));
    }

    /** What the calls log: slf4j-simple writes to {@link System#err}. */
    private static String logOf(Runnable calls) {
        PrintStream original = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            calls.run();
        } finally {
            System.setErr(original);
        }
        return captured.toString(StandardCharsets.UTF_8);
    }
}
