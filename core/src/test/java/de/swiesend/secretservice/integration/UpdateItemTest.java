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
 * {@code updateItem} changes an item's label, attributes and secret, and reports whether it did.
 */
class UpdateItemTest {

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
    void everyPartIsChanged() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();

        assertTrue(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", "new-secret", Map.of("k", "v")));
        assertEquals(List.of("Label", "Attributes"), fake.itemPropertySets(), "the label and the attributes were set");
        assertEquals(1, fake.setSecretCalls(), "and the secret");
    }

    @Test
    void aRefusedLabelOrAttributeChangeFailsTheUpdate() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRefuseItemPropertyChanges(true);

        assertFalse(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", "new-secret", Map.of("k", "v")),
                "the provider refused the label and the attributes, so the update failed");
        assertEquals(1, fake.setSecretCalls(), "the secret was set all the same, as in 1.x");
    }
}
