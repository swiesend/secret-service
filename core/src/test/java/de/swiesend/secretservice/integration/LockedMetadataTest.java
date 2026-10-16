package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.SearchMode;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * What a locked collection shows of its items is not always theirs: gnome-keyring shows an item of a
 * keyring that it loaded locked with an empty label, and each attribute as
 * {@code gkr:compat:hashed:<name>} with the MD5 of its value. The library answers nothing for them,
 * instead of answering those as the item's.
 *
 * <p>Against {@link FakeSecretService}, which shows a locked item so when asked to.</p>
 */
class LockedMetadataTest {

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

    private String itemWithAttributes(CollectionInterface collection) {
        return collection.createItem("probe label", "probe-secret", Map.of("app", "probe-app")).orElseThrow();
    }

    /** Locks the collection where the library cannot unlock it again: prompting is disabled. */
    private void lock(CollectionInterface collection) {
        harness.fake().setRequirePromptForCollectionUnlock(true);
        harness.fake().lockCollection();
        collection.disablePrompt();
    }

    @Test
    void aLockedItemShowsNeitherHashedAttributesNorAnEmptyLabel() throws Exception {
        CollectionInterface collection = harness.start(false);
        String path = itemWithAttributes(collection);
        harness.fake().setHashLockedMetadata(true);
        lock(collection);

        assertEquals(Optional.empty(), collection.getAttributes(path), "not gkr:compat:hashed:app and an MD5");
        assertEquals(Optional.empty(), collection.getItemLabel(path), "not an empty label");
        assertEquals(List.of(), collection.search("gkr", SearchMode.BY_ATTRIBUTE_KEY), "no hashed key matches");
    }

    @Test
    void aLockedItemThatShowsItsOwnMetadataKeepsIt() throws Exception {
        // As KeePassXC shows an item that it locks for the client until the user confirms access.
        CollectionInterface collection = harness.start(false);
        String path = itemWithAttributes(collection);
        lock(collection);

        assertEquals(Optional.of(Map.of("app", "probe-app")), collection.getAttributes(path));
        assertEquals(Optional.of("probe label"), collection.getItemLabel(path));
    }

    @Test
    void anUnlockedItemShowsItsMetadata() throws Exception {
        CollectionInterface collection = harness.start(false);
        String path = itemWithAttributes(collection);
        harness.fake().setHashLockedMetadata(true);

        assertEquals(Optional.of(Map.of("app", "probe-app")), collection.getAttributes(path));
        assertEquals(Optional.of("probe label"), collection.getItemLabel(path));
        assertEquals(List.of(path), collection.search("probe", SearchMode.BY_NAME));
    }
}
