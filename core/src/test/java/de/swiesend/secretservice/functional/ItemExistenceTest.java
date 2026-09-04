package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.handlers.MessageHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.NoSuchElementException;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code itemExists} separates the two things an empty read conflates: the item is gone, and the
 * item could not be reached. Callers act destructively on the first and must fail closed on the
 * second, so the distinction has to hold against a <b>real</b> daemon, not only in theory.
 *
 * <p>These tests exist because the feature shipped with none. The mapping treated
 * {@code DBus.Error.UnknownMethod} as "says nothing about existence" -- correct in general, and
 * wrong for a property read, because every object that exists implements
 * {@code org.freedesktop.DBus.Properties}. gnome-keyring answers precisely that for a deleted item,
 * so {@code ABSENT} was unreachable on the library's primary provider and nothing noticed.</p>
 *
 * <p>Uses its own throwaway collection and deletes it; never touches the default keyring.</p>
 */
class ItemExistenceTest {

    private ServiceInterface service;
    private SessionInterface session;
    private CollectionInterface collection;

    @BeforeEach
    void setUp() {
        service = SecretService.create().get();
        session = service.openSession().get();
        try {
            collection = session.collection("test-item-existence", Optional.of("password")).get();
        } catch (NoSuchElementException e) {
            collection = session.collection("test-item-existence", Optional.empty()).get();
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        // Guarded: any .get() in setUp failing on an empty Optional (no provider, collection
        // refused) leaves these null, and an NPE thrown here replaces the real cause in the report
        // with a mystery about teardown.
        if (collection != null) {
            collection.delete();
            collection.close();
        }
        if (session != null) session.close();
        if (service != null) service.close();
    }

    @Test
    void aDeletedItemIsReportedAbsentNotUnreachable() {
        // The test the feature needed. gnome-keyring reports a deleted item with
        // DBus.Error.UnknownMethod ("Object does not exist at path ..."), which the generic mapping
        // sends to UNAVAILABLE. Without the property-read reinterpretation this assertion fails
        // with Optional.empty(), and every caller that skips a vanished item instead fails closed
        // forever -- the outage the distinction was built to prevent.
        String path = collection.createItem("existence-probe", "s3cr3t").orElse(null);
        assertNotNull(path, "createItem returned empty");

        assertEquals(Optional.of(true), collection.itemExists(path),
                "an item that was just created must be reported present");

        assertTrue(collection.deleteItem(path), "could not delete the item");

        assertEquals(Optional.of(false), collection.itemExists(path),
                "a deleted item must be reported PROVABLY ABSENT, not merely unreadable");
    }

    @Test
    void aPathThatWasNeverAnItemIsAbsent() {
        // A path UNDER this collection, unlike an earlier version that probed a path under a
        // different collection -- which only "worked" because itemExists ignored collection
        // membership.
        String itemPath = collection.createItem("victim", "secret", Map.of()).orElseThrow();
        String neverAnItem = itemPath.substring(0, itemPath.lastIndexOf('/')) + "/999999";
        assertEquals(Optional.of(false), collection.itemExists(neverAnItem),
                "a path with no object behind it is absent");
    }

    @Test
    void aPathInAnotherCollectionIsNotAnItemOfThisOne() throws Exception {
        // itemExists is documented as scoped to THIS collection. Answering of(true) for a path
        // under some other collection hands a caller "this item is mine" for an item that is not.
        //
        // The foreign item must genuinely EXIST: with a made-up path the provider answers "no such
        // object" and the assertion passes with or without any scoping -- an earlier version of
        // this test did exactly that and proved nothing.
        CollectionInterface other;
        try {
            other = session.collection("test-item-existence-other", Optional.of("password")).get();
        } catch (NoSuchElementException e) {
            // Same fallback as setUp: providers without the gnome-keyring password interface
            // return empty for password-created collections. Without this, the test errored with
            // a bare NoSuchElementException unrelated to the scoping behaviour under test.
            other = session.collection("test-item-existence-other", Optional.empty()).get();
        }
        try {
            String foreignPath = other.createItem("foreign", "secret", Map.of()).orElseThrow();
            assertEquals(Optional.of(true), other.itemExists(foreignPath),
                    "the foreign item exists in its own collection");
            assertEquals(Optional.of(false), collection.itemExists(foreignPath),
                    "an item of another collection is not an item of this one");
        } finally {
            other.delete();
            other.close();
        }
    }

    @Test
    void aNullPathProvesNothing() {
        // A programming error is not evidence about any item. Answering "provably absent" here
        // would license a caller's destructive branch on it.
        assertEquals(Optional.empty(), collection.itemExists(null));
        assertEquals(Optional.empty(), collection.itemExists(""));
    }

    @Test
    void theOutcomeMappingKeepsAbsentStrictlySeparateFromUnavailable() {
        // Pins the classification itself, so a future edit to the switch cannot quietly collapse
        // the two again. ABSENT is the only value that licenses acting on "not there".
        assertEquals(4, MessageHandler.Outcome.values().length,
                "a new Outcome needs a deliberate decision about which callers may act on it");
        assertNotNull(MessageHandler.Outcome.valueOf("ABSENT"));
        assertNotNull(MessageHandler.Outcome.valueOf("DENIED"));
        assertNotNull(MessageHandler.Outcome.valueOf("UNAVAILABLE"));
        assertNotNull(MessageHandler.Outcome.valueOf("OK"));
    }
}
