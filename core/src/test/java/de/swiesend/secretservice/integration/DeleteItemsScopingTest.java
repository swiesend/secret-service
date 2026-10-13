package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code deleteItems} checks every path before it acts. One path under another collection refuses
 * the whole call, and the refusal comes before {@code unlockWithUserPermission}, so a refused call
 * raises no unlock prompt and deletes nothing -- not even the items that do belong to the
 * collection.
 *
 * <p>Against {@link FakeSecretService}, because the proof is what the provider did <em>not</em>
 * receive, and only the fake records every call.</p>
 */
class DeleteItemsScopingTest {

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
    void aForeignPathRefusesTheWholeCallBeforeAnythingIsSent() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        String foreign = fake.addItem(fake.addCollection("other"), "foreign", "foreign-secret", Map.of());
        List<String> before = fake.calls();

        assertFalse(collection.deleteItems(List.of(FakeSecretService.ITEM_PATH, foreign)),
                "a list that names an item of another collection is refused");

        assertEquals(before, fake.calls(),
                "the refusal comes first: no lock, no unlock and no delete reached the provider");
        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH),
                "all or nothing: the collection's own item is kept");
        assertTrue(fake.hasItem(foreign), "the other collection's item is kept");
    }
}
