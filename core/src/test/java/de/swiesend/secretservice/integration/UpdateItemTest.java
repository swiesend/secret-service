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
    void withoutANewSecretTheLabelAndAttributesAreChanged() throws Exception {
        // How 1.x callers rename an item: updateItem(path, label, null, attributes).
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();

        assertTrue(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", null, Map.of("k", "v")));
        assertEquals(List.of("Label", "Attributes"), fake.itemPropertySets(), "the label and the attributes were set");
        assertEquals(0, fake.setSecretCalls(), "and the secret was left as it is");
    }

    @Test
    void aNewSecretIsNotSentToALockedItem() throws Exception {
        // The fake accepts a secret for a locked item and keeps nothing of it, as KWallet does.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);

        assertFalse(collection.updateItem(FakeSecretService.ITEM_PATH, null, "new-secret", null),
                "a secret for a locked item is not reported as set");
        assertEquals(0, fake.setSecretCalls(), "nor is it sent");
    }

    @Test
    void theLabelOfALockedItemIsStillSent() throws Exception {
        // The counterpart of the test above: only the secret is held back. KWallet keeps a label
        // that it gets for a locked item, as through setItemLabel.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);

        assertTrue(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", null, null));
        assertEquals(List.of("Label"), fake.itemPropertySets());
    }

    @Test
    void anEmptySecretIsRefused() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();

        assertFalse(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", "", null));
        assertEquals(List.of(), fake.itemPropertySets(), "nothing was changed");
        assertEquals(0, fake.setSecretCalls());
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
