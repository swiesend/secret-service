package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Failure.Reason;
import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Result;
import de.swiesend.secretservice.functional.ConsentPolicy;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code storeItem} stores a secret under its attributes: it updates the one item that has them,
 * creates an item where none has, and changes nothing where several have. Against
 * {@link FakeSecretService}.
 */
class StoreItemTest {

    private static final Map<String, String> ATTRIBUTES = Map.of("app", "store-test", "user", "alice");

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private CollectionInterface collection;

    @BeforeEach
    void start() throws Exception {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(), "dbus-daemon is not on the PATH");
        collection = harness.start(false);
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    private String stored(Result<String> result) {
        return result.value().orElseThrow(() -> new AssertionError(result.toString()));
    }

    private Optional<String> secretOf(String path) {
        return collection.withSecret(path, String::new);
    }

    @Test
    void anItemThatNoneHasIsCreated() {
        String path = stored(collection.storeItem("token", "first", ATTRIBUTES));

        assertEquals(Optional.of("first"), secretOf(path));
        assertEquals(Optional.of(List.of(path)), collection.getItems(ATTRIBUTES));
    }

    @Test
    void theItemThatHasTheAttributesIsUpdatedNotDuplicated() {
        String path = stored(collection.storeItem("token", "first", ATTRIBUTES));

        assertEquals(Result.ok(path), collection.storeItem("renamed", "second", ATTRIBUTES));
        assertEquals(Optional.of("second"), secretOf(path));
        assertEquals(Optional.of("renamed"), collection.getItemLabel(path));
        assertEquals(Optional.of(List.of(path)), collection.getItems(ATTRIBUTES), "one item, not two");
    }

    @Test
    void anItemWithMoreAttributesIsTheItem() {
        // As getItems matches: every attribute given, with the same value.
        String path = collection.createItem("token", "first",
                Map.of("app", "store-test", "user", "alice", "host", "build-1")).orElseThrow();

        assertEquals(Result.ok(path), collection.storeItem("token", "second", ATTRIBUTES));
        assertEquals(Optional.of("second"), secretOf(path));
    }

    @Test
    void severalItemsWithTheAttributesAreAmbiguousAndNoneChanges() {
        String one = collection.createItem("one", "first", ATTRIBUTES).orElseThrow();
        String other = collection.createItem("other", "first", ATTRIBUTES).orElseThrow();

        assertEquals(Optional.of(Reason.AMBIGUOUS), collection.storeItem("token", "second", ATTRIBUTES).reason());
        assertEquals(Optional.of("first"), secretOf(one));
        assertEquals(Optional.of("first"), secretOf(other));
        assertEquals(2, collection.getItems(ATTRIBUTES).orElseThrow().size(), "no third item");
    }

    @Test
    void aLockedCollectionThatStaysLockedIsLocked() {
        harness.fake().setRequirePromptForCollectionUnlock(true);
        harness.fake().lockCollection();
        collection.disablePrompt();

        assertEquals(Optional.of(Reason.LOCKED), collection.storeItem("token", "first", ATTRIBUTES).reason());
    }

    @Test
    void anUpdateThatTheConsentPolicyRefusesIsDenied() {
        String path = stored(collection.storeItem("token", "first", ATTRIBUTES));
        collection.setConsentPolicy(ConsentPolicy.none()
                .require(ConsentPolicy.Operation.WRITE, ConsentPolicy.Requirement.CALLBACK)
                .handler(request -> false));

        assertEquals(Optional.of(Reason.DENIED), collection.storeItem("token", "second", ATTRIBUTES).reason());
        assertEquals(Optional.of("first"), secretOf(path));
    }

    @Test
    void theArgumentsAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> collection.storeItem(" ", "first", ATTRIBUTES));
        assertThrows(IllegalArgumentException.class, () -> collection.storeItem("token", "", ATTRIBUTES));
        assertThrows(IllegalArgumentException.class, () -> collection.storeItem("token", "first", Map.of()));
        assertThrows(NullPointerException.class, () -> collection.storeItem("token", "first", null));
    }
}
