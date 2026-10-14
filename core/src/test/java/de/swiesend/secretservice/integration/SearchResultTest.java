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
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code search()} promises an unmodifiable list. For an empty query, which matches every item, it
 * handed out the list it had built, and a caller could change it.
 */
class SearchResultTest {

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
    void anEmptyQueryReturnsEveryItemUnmodifiable() throws Exception {
        CollectionInterface collection = harness.start(false);

        List<String> substring = collection.search("", SearchMode.BY_NAME);
        List<String> fuzzy = collection.search("", SearchMode.BY_NAME, 2);

        assertEquals(List.of(FakeSecretService.ITEM_PATH), substring, "an empty query matches every item");
        assertEquals(List.of(FakeSecretService.ITEM_PATH), fuzzy, "also with fuzzy matching");
        assertThrows(UnsupportedOperationException.class, () -> substring.add("/x"), "the list is unmodifiable");
        assertThrows(UnsupportedOperationException.class, () -> fuzzy.add("/x"), "also with fuzzy matching");
    }
}
