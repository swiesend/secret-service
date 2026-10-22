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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code updateItem} changes an item's label, attributes and secret, and reports whether it did. A
 * locked item it unlocks first, and leaves as it is when it stays locked.
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
        // KWallet accepts a secret for a locked item and keeps nothing of it.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.KWALLET_DROPS_THE_SECRET_FOR_A_LOCKED_ITEM);
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);

        assertFalse(collection.updateItem(FakeSecretService.ITEM_PATH, null, "new-secret", null),
                "a secret for a locked item is not reported as set");
        assertEquals(0, fake.setSecretCalls(), "nor is it sent");
    }

    @Test
    void theLabelOfALockedItemIsNotSent() throws Exception {
        // KWallet keeps a label that it gets for an item of a closed wallet.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.KWALLET_TAKES_THE_LABEL_OF_A_LOCKED_ITEM);
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);

        assertFalse(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", null, Map.of("k", "v")),
                "a locked item is not changed");
        assertEquals(List.of(), fake.itemPropertySets(), "neither its label nor its attributes");
    }

    @Test
    void aLockedItemIsUnlockedFirst() throws Exception {
        // KeePassXC keeps an item locked for a client until the user confirms its access, and
        // takes a new label and attributes for it all the same; only the secret it refuses.
        CollectionInterface collection = harness.start(true);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.KEEPASSXC_CHANGES_AN_ITEM_IT_HAS_NOT_ALLOWED);
        fake.setRequirePromptForItemOps(true);

        assertTrue(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", "new-secret", Map.of("k", "v")));
        assertEquals(List.of(FakeSecretService.ITEM_PATH), fake.unlockCalls(), "the item was unlocked through its prompt");
        assertEquals(List.of("Label", "Attributes"), fake.itemPropertySets(), "then every part was set");
        assertEquals(1, fake.setSecretCalls());
    }

    @Test
    void anItemThatStaysLockedIsNotChanged() throws Exception {
        // The user dismisses the dialog that would confirm the access.
        CollectionInterface collection = harness.start(true);
        FakeSecretService fake = harness.fake();
        fake.setDismissPrompts(true);

        assertFalse(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", "new-secret", Map.of("k", "v")));
        assertEquals(List.of(FakeSecretService.ITEM_PATH), fake.unlockCalls(), "asked once");
        assertEquals(List.of(), fake.itemPropertySets(), "neither the label nor the attributes were set");
        assertEquals(0, fake.setSecretCalls(), "nor the secret");
    }

    @Test
    void setItemLabelSendsNoLabelToALockedItem() throws Exception {
        // As for updateItem: KWallet keeps a label that it gets for an item of a closed wallet.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.KWALLET_TAKES_THE_LABEL_OF_A_LOCKED_ITEM);
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);

        assertFalse(collection.setItemLabel(FakeSecretService.ITEM_PATH, "renamed"), "a locked item is not changed");
        assertEquals(List.of(), fake.itemPropertySets());
    }

    @Test
    void setItemLabelUnlocksALockedItemFirst() throws Exception {
        // KeePassXC takes a new label for an item that it keeps locked for the client.
        CollectionInterface collection = harness.start(true);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.KEEPASSXC_CHANGES_AN_ITEM_IT_HAS_NOT_ALLOWED);
        fake.setRequirePromptForItemOps(true);

        assertTrue(collection.setItemLabel(FakeSecretService.ITEM_PATH, "renamed"));
        assertEquals(List.of(FakeSecretService.ITEM_PATH), fake.unlockCalls(), "the item was unlocked through its prompt");
        assertEquals(List.of("Label"), fake.itemPropertySets());
    }

    @Test
    void setItemLabelWithPromptingDisabledLeavesALockedItem() throws Exception {
        CollectionInterface collection = harness.start(true);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.KEEPASSXC_CHANGES_AN_ITEM_IT_HAS_NOT_ALLOWED);
        assertTrue(collection.disablePrompt());

        assertFalse(collection.setItemLabel(FakeSecretService.ITEM_PATH, "renamed"));
        assertEquals(List.of(), fake.unlockCalls(), "no unlock, which needs the prompt");
        assertEquals(List.of(), fake.itemPropertySets());
    }

    @Test
    void withPromptingDisabledALockedItemIsNotChanged() throws Exception {
        CollectionInterface collection = harness.start(true);
        FakeSecretService fake = harness.fake();
        assertTrue(collection.disablePrompt());

        assertFalse(collection.updateItem(FakeSecretService.ITEM_PATH, "renamed", null, null));
        assertEquals(List.of(), fake.unlockCalls(), "no unlock, which needs the prompt");
        assertEquals(List.of(), fake.itemPropertySets());
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
