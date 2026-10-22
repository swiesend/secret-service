package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.interfaces.Item;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * oo7 takes every item to have attributes: its {@code CreateItem} unwraps the {@code Attributes}
 * property, and without it the call fails with no answer. {@code createItem(label, secret)} sent no
 * attributes.
 *
 * <p>Against {@link FakeSecretService}, which records the properties of {@code CreateItem}. With
 * prompting disabled: the fake creates an item through a prompt, and the properties are in
 * {@code CreateItem} itself.</p>
 */
class CreateItemPropertiesTest {

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
    void anItemWithoutAttributesIsCreatedWithAnEmptyMap() throws Exception {
        // oo7 gives no reply to a CreateItem without the attributes.
        CollectionInterface collection = harness.start(false);
        harness.fake().reproduce(ProviderBug.OO7_PANICS_ON_CREATE_ITEM_WITHOUT_ATTRIBUTES);
        assertTrue(collection.disablePrompt());

        collection.createItem("new", "secret");

        assertEquals(List.of(Set.of(Item.LABEL, Item.ATTRIBUTES)), harness.fake().createItemPropertyNames());
    }

    @Test
    void anItemWithAttributesIsCreatedWithThem() throws Exception {
        // The counterpart of the test above: the same two properties.
        CollectionInterface collection = harness.start(false);
        assertTrue(collection.disablePrompt());

        collection.createItem("new", "secret", Map.of("application", "test"));

        assertEquals(List.of(Set.of(Item.LABEL, Item.ATTRIBUTES)), harness.fake().createItemPropertyNames());
    }
}
