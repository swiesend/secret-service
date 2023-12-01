package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CollectionTest {

    private static final Logger log = LoggerFactory.getLogger(CollectionTest.class);

    ServiceInterface service = null;

    SessionInterface session = null;

    CollectionInterface collection = null;

    @BeforeEach
    void setUp() {
        service = SecretService.create().get();
        session = service.openSession().get();
        try {
            collection = session.collection("test-collection", Optional.of("password")).get();
        } catch (NoSuchElementException e) {
            collection = session.collection("test-collection", Optional.empty()).get();
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        collection.delete();
        collection.close();
        session.close();
        service.close();
    }

    @Test
    void clear() {
        assertTrue(collection.clear());
    }

    @Test
    void createItem() {
        for (String i : Arrays.asList("a", "b", "c")) {
            String item = collection.createItem(i, i).get();
            assertTrue(item.startsWith("/org/freedesktop/secrets/collection/test_2dcollection/"));
            String label = collection.getItemLabel(item).get();
            assertEquals(i, label);
            char[] secret = collection.getSecret(item).get();
            assertEquals(i, new String(secret));
        }
    }

    @Test
    void createItemWithAttribute() {
        for (String i : Arrays.asList("a", "b", "c")) {
            Map<String, String> expectedAttributes = Map.of(i, i, i + i, i + i);
            String item = collection.createItem(i, i, expectedAttributes).get();
            assertTrue(item.startsWith("/org/freedesktop/secrets/collection/test_2dcollection/"));

            String label = collection.getItemLabel(item).get();
            assertEquals(i, label);

            char[] secret = collection.getSecret(item).get();
            assertEquals(i, new String(secret));

            Map<String, String> actualAttributes = collection.getAttributes(item).get();
            for (Map.Entry<String, String> entry : actualAttributes.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                log.info(key + ": " + value);
            }
            assertEquals(expectedAttributes.size(), actualAttributes.size());
            for (Map.Entry<String, String> entry : expectedAttributes.entrySet()) {
                String key = entry.getKey();
                String expectedValue = entry.getValue();
                String actualValue = actualAttributes.get(key);
                assertEquals(expectedValue, actualValue);
            }
        }
    }

    @Test
    void delete() {
        assertTrue(collection.delete());
    }

    @Test
    void deleteALockedCollection() {
        assertTrue(collection.lock());
        assertTrue(collection.delete());
    }

    @Test
    void deleteWithALockedService() {
        assertTrue(service.getService().lockService());
        assertTrue(collection.delete());
    }

    @Test
    @Disabled
    // TODO: test password abort
    void deleteCollectionWithoutPassword() {
        CollectionInterface collectionWithoutPassword = service.openSession()
                .flatMap(session ->
                        session.collection("test-no-password-collection", Optional.empty())
                ).get();
        collectionWithoutPassword.disablePrompt();
        assertTrue(collectionWithoutPassword.delete());
    }

    @Test
    void deleteItem() {
        String item = null;
        item = collection.createItem("test", "secret").get();
        assertTrue(collection.deleteItem(item));
        assertTrue(collection.getSecret(item).isEmpty());

        Map<String, String> attributes = Map.of("key", "value");
        item = collection.createItem("test", "secret", attributes).get();
        assertTrue(collection.deleteItem(item));
        assertTrue(collection.getSecret(item).isEmpty());
    }

    @Test
    void deleteItems() {
        String item1 = collection.createItem("test", "secret1").get();
        String item2 = collection.createItem("test", "secret2").get();
        assertTrue(collection.deleteItems(List.of(item1, item2)));
        assertTrue(collection.getSecret(item1).isEmpty());
        assertTrue(collection.getSecret(item2).isEmpty());
    }

    @Test
    void getAttributes() {
        String item = null;
        Optional<Map<String, String>> maybeAttributes;
        Map<String, String> emptyMap = Map.of();
        ;

        item = collection.createItem("test", "secret").get();
        maybeAttributes = collection.getAttributes(item);
        assertTrue(maybeAttributes.isPresent());
        assertEquals(emptyMap, maybeAttributes.get());

        Map<String, String> attributes = Map.of("key", "value");
        item = collection.createItem("test", "secret", attributes).get();
        maybeAttributes = collection.getAttributes(item);
        assertTrue(maybeAttributes.isPresent());
        assertEquals(attributes, maybeAttributes.get());
    }

    @Test
    void getItems() throws InterruptedException {
        Map<String, String> attributes = Map.of("key", "value-1");
        String item1 = collection.createItem("item-1", "secret", attributes).get();
        String item2 = collection.createItem("item-2", "secret", Map.of("key", "value-2")).get();
        String item3 = collection.createItem("item-3", "secret", attributes).get();
        Optional<List<String>> maybeItems = collection.getItems(attributes);
        assertTrue(maybeItems.isPresent());
        List<String> items = maybeItems.get();
        assertEquals(2, items.size());
    }

    @Test
    void getItemLabel() {
        String item = collection.createItem("item-1", "secret").get();
        Optional<String> maybeLabel = collection.getItemLabel(item);
        assertTrue(maybeLabel.isPresent());
        assertEquals("item-1", maybeLabel.get());
    }

    @Test
    @Disabled
    void setItemLabel() {
        String item = collection.createItem("item-original", "secret").get();
        assertTrue(collection.setItemLabel(item, "item-override"));
        Optional<String> maybeLabel = collection.getItemLabel(item);
        assertTrue(maybeLabel.isPresent());
        assertEquals("item-override", maybeLabel.get());
    }

    @Test
    void setLabel() {
        assertEquals("test-collection", collection.getLabel().get());
        assertTrue(collection.setLabel("override"));
        assertEquals("override", collection.getLabel().get());
    }

    @Test
    void getLabel() {
        assertEquals("test-collection", collection.getLabel().get());
    }

    @Test
    void getId() {
        assertEquals("test_2dcollection", collection.getId().get());
    }

    // collection.lockItem(item1); // TODO: test lockItem()

    @Test
    void getSecret() {
        String item1 = collection.createItem("item-1", "secret-1").get();
        String item2 = collection.createItem("item-2", "secret-2").get();

        Optional<char[]> maybeSecret2 = collection.getSecret(item2);
        assertTrue(maybeSecret2.isPresent());
        assertEquals("secret-2", new String(maybeSecret2.get()));

        Optional<char[]> maybeSecret1 = collection.getSecret(item1);
        assertTrue(maybeSecret1.isPresent());
        assertEquals("secret-1", new String(maybeSecret1.get()));
    }

    @Test
    void getSecrets() {
        Map<String, String> attributes = Map.of("key", "value-1");
        String item1 = collection.createItem("item-1", "secret-1", attributes).get();
        String item2 = collection.createItem("item-2", "secret-2", Map.of("key", "value-2")).get();
        String item3 = collection.createItem("item-3", "secret-3", attributes).get();
        Optional<Map<String, char[]>> maybeSecrets = collection.getSecrets();
        assertTrue(maybeSecrets.isPresent());
        assertEquals(3, maybeSecrets.get().size());
        assertEquals(Map.of(
                item1, "secret-1",
                item2, "secret-2",
                item3, "secret-3"
        ), maybeSecrets.map(m -> m
                .entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> String.valueOf(e.getValue())
                ))
        ).get());
    }

    @Test
    void isLocked() {
        String item1 = collection.createItem("item-1", "secret-1").get();

        assertTrue(!collection.isLocked());
        assertTrue(collection.lock());
        assertTrue(collection.isLocked());

        Optional<char[]> maybeItem1 = collection.getSecret(item1);
        assertTrue(maybeItem1.isPresent());
        assertTrue(!collection.isLocked());
    }

    @Test
    void lock() {
        assertTrue(collection.lock());
        assertTrue(collection.isLocked());
    }

    @Test
    void unlockWithUserPermission() {
        collection.lock();
        assertTrue(collection.unlockWithUserPermission());
        assertTrue(!collection.isLocked());
    }

    @Test
    void updateItem() {
        Map<String, String> attributes = Map.of("key", "value-1");
        String item1 = collection.createItem("item-1", "secret-1", attributes).get();

        Map<String, String> attributesOverride = Map.of("key", "value-override");
        assertTrue(collection.updateItem(item1, "item-1-override", "secret-1-override", attributesOverride));
        assertEquals(0, collection.getItems(attributes).get().size());
        List<String> updatedItems = collection.getItems(attributesOverride).get();
        assertEquals(1, updatedItems.size());
        assertEquals(item1, updatedItems.get(0));
        assertEquals("item-1-override", collection.getItemLabel(item1).get());
        assertEquals("secret-1-override", new String(collection.getSecret(item1).get()));
        Map<String, String> actualAttributes = collection.getAttributes(item1).get();
        assertEquals("value-override", actualAttributes.get("key"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", actualAttributes.get("xdg:schema"));
        }
    }

    @Test
    void close() throws Exception {
        collection.close();
        assertTrue(collection.lock());
        collection.disablePrompt();
        assertTrue(!collection.unlockWithUserPermission());
        collection.enablePrompt();
    }
}