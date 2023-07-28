package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CollectionTest {

    private static final Logger log = LoggerFactory.getLogger(CollectionTest.class);

    ServiceInterface service = null;
    CollectionInterface collection = null;

    @BeforeEach
    void setUp() {
        service = SecretService.create().get();
        collection = service
                .openSession()
                .flatMap(session -> session.collection("test-collection", Optional.of("collection")))
                .get();
    }

    @AfterEach
    void tearDown() throws Exception {
        collection.delete();
        collection.close();
        service.close();
    }

    @Test
    @Disabled
        // TODO
    void clear() {
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
    @Disabled
    void deleteWithALockedService() {
        assertTrue(service.getService().lockService());
        assertTrue(collection.delete());
    }

    @Test
    @Disabled
        // TODO: test password abort
    void deleteCollectionWithoutPassword() {
        CollectionInterface collectionWithoutPassword = service
                .openSession()
                .flatMap(session -> session.collection("test-no-password-collection", Optional.empty()))
                .get();
        assertTrue(collectionWithoutPassword.delete());
    }

    @Test
    @Disabled
        // TODO
    void deleteItem() {
    }

    @Test
    @Disabled
        // TODO
    void deleteItems() {
    }

    @Test
    @Disabled
        // TODO
    void getAttributes() {
    }

    @Test
    @Disabled
        // TODO
    void getItems() {
    }

    @Test
    @Disabled
        // TODO
    void getItemLabel() {
    }

    @Test
    @Disabled
        // TODO
    void setItemLabel() {
    }

    @Test
    @Disabled
        // TODO
    void setLabel() {
    }

    @Test
    @Disabled
        // TODO
    void getLabel() {
    }

    @Test
    @Disabled
        // TODO
    void getId() {
    }

    @Test
    @Disabled
        // TODO
    void getSecret() {
    }

    @Test
    @Disabled
        // TODO
    void getSecrets() {
    }

    @Test
    @Disabled
        // TODO
    void isLocked() {
    }

    @Test
    @Disabled
        // TODO
    void lock() {
    }

    @Test
    @Disabled
        // TODO
    void unlockWithUserPermission() {
    }

    @Test
    @Disabled
        // TODO
    void updateItem() {
    }

    @Test
    @Disabled
        // TODO
    void close() {
    }
}