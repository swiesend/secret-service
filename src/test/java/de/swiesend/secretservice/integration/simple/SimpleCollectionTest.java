package de.swiesend.secretservice.integration.simple;

import de.swiesend.secretservice.simple.SimpleCollection;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class SimpleCollectionTest {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollectionTest.class);

    @Test
    @Disabled("Danger Zone! Be aware that this can lead to the loss of passwords.")
    public void deleteDefaultCollection() throws IOException {
        SimpleCollection defaultCollection = new SimpleCollection();
        assertThrows(SecurityException.class, defaultCollection::delete);
    }

    @Test
    public void deleteNonDefaultCollection() throws IOException {
        SimpleCollection collection = new SimpleCollection("test", "test");
        assertDoesNotThrow(collection::delete);
    }

    @Test
    public void createPasswordWithoutAttributes() throws IOException {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");

        String item = collection.createItem("item", "sécrèt");
        assertEquals("item", collection.getLabel(item));
        char[] secret = collection.getSecret(item);
        assertArrayEquals("sécrèt".toCharArray(), secret);
        Arrays.fill(secret, '\0');
        Map<String, String> actualAttributes = collection.getAttributes(item);
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        } else {
            assertEquals(Collections.emptyMap(), collection.getAttributes(item));
        }

        // after
        collection.deleteItem(item);
        collection.delete();
    }

    @Test
    public void createPasswordWithAttributes() throws IOException {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");

        Map<String, String> attributes = new HashMap<>();
        attributes.put("uuid", UUID.randomUUID().toString());

        String item = collection.createItem("item", "secret", attributes);
        assertEquals("item", collection.getLabel(item));
        char[] secret = collection.getSecret(item);
        assertArrayEquals("secret".toCharArray(), secret);
        Arrays.fill(secret, '\0');
        Map<String, String> actualAttributes = collection.getAttributes(item);
        assertEquals(attributes.get("uuid"), actualAttributes.get("uuid"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        }

        // after
        collection.deleteItem(item);
        collection.delete();
    }

    @Test
    public void updatePassword() throws IOException {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");
        Map<String, String> attributes = new HashMap<>();

        // create password
        attributes.put("uuid", UUID.randomUUID().toString());
        log.info("attributes: " + attributes);

        String item = collection.createItem("item", "secret", attributes);
        assertEquals("item", collection.getLabel(item));
        char[] secret = collection.getSecret(item);
        assertArrayEquals("secret".toCharArray(), secret);
        Arrays.fill(secret, '\0');
        Map<String, String> actualAttributes = collection.getAttributes(item);
        assertEquals(attributes.get("uuid"), actualAttributes.get("uuid"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        }

        // update password
        attributes.put("uuid", UUID.randomUUID().toString());
        log.info("attributes: " + attributes);
        collection.updateItem(item, "updated item", "updated secret", attributes);
        assertEquals("updated item", collection.getLabel(item));
        char[] updatedSecret = collection.getSecret(item);
        assertArrayEquals("updated secret".toCharArray(), updatedSecret);
        Arrays.fill(updatedSecret, '\0');
        actualAttributes = collection.getAttributes(item);
        assertEquals(attributes.get("uuid"), actualAttributes.get("uuid"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        }

        // after
        collection.deleteItem(item);
        collection.delete();
    }

    @Test
    public void getItems() throws IOException {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");

        // create password
        Map<String, String> attributes = new HashMap<>();
        attributes.put("uuid", UUID.randomUUID().toString());
        log.info("attributes: " + attributes);
        String item = collection.createItem("item", "secret", attributes);

        // search for items by attributes
        List<String> items = collection.getItems(attributes);
        assertEquals(1, items.size());

        // after
        collection.deleteItem(item);
        collection.delete();
    }

    @Test
    @Disabled
    public void getPasswordFromDefaultCollection() throws IOException {
        // before
        SimpleCollection collection = new SimpleCollection();
        String item = collection.createItem("item", "secret");

        // test
        char[] password = collection.getSecret(item);
        assertArrayEquals("secret".toCharArray(), password);
        Arrays.fill(password, '\0');

        // after
        collection.deleteItem(item);
    }

    @Test
    public void getPasswordFromNonDefaultCollection() throws IOException {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");
        String itemID = collection.createItem("item", "secret");

        // test
        char[] password = collection.getSecret(itemID);
        assertArrayEquals("secret".toCharArray(), password);
        Arrays.fill(password, '\0');

        // after
        collection.deleteItem(itemID);
        collection.delete();
    }

    @Test
    public void unlockNonDefaultCollectionSilently() throws IOException {
        // before
        SimpleCollection create = new SimpleCollection("test", "test");
        String itemID = create.createItem("item", "secret");
        create.lock();

        // test
        SimpleCollection collection = new SimpleCollection("test", "test");

        char[] password = collection.getSecret(itemID);
        assertArrayEquals("secret".toCharArray(), password);
        Arrays.fill(password, '\0');

        // after
        collection.deleteItem(itemID);
        collection.delete();
    }

    @Test
    @Disabled
    public void getPasswords() throws IOException {
        SimpleCollection collection = new SimpleCollection();
        assertDoesNotThrow(() -> {
            Map<String, char[]> secrets = collection.getSecrets();
            assertNotNull(secrets);
            for (char[] ignored : secrets.values()) {
                log.info("secrets: ***");
            }
        });
    }

    @Test
    @Disabled("Danger Zone!  Be aware that this can lead to the loss of passwords if performed for other items.")
    public void deletePassword() throws IOException {
        SimpleCollection collection = new SimpleCollection();
        String item = collection.createItem("item", "secret");
        assertDoesNotThrow(() -> {
            collection.deleteItem(item);
        });
    }

    /**
     * Potential Danger Zone! Be aware that this can lead to the loss of passwords if performed on the default collection.
     */
    @Test
    public void deletePasswords() throws IOException {
        SimpleCollection collection = new SimpleCollection("test", "test");
        List<String> items = Arrays.asList(
                collection.createItem("item-1", "secret"),
                collection.createItem("item-2", "secret")
        );
        assertDoesNotThrow(() -> collection.deleteItems(items));
        collection.delete();
    }

    /**
     * Assuming you test on a system, where the secret-service is actually available.
     */
    @Test
    public void isAvailable() {
        assertTrue(SimpleCollection.isAvailable());
    }

    @Test
    @Disabled
    public void setTimeout() throws IOException {
        SimpleCollection collection = new SimpleCollection();
        String item = collection.createItem("item", "secret");

        // wait 3 seconds before cancelling the prompt manually
        Duration briefly = Duration.ofSeconds(3);
        collection.setTimeout(briefly);
        try {
            @SuppressWarnings("unused")
            Map<String, char[]> ignored = collection.getSecrets();
        } catch (SecurityException e) {
            log.info("Expected SecurityException:", e);
        }

        // clean within 120 seconds
        Duration longish = Duration.ofSeconds(120);
        collection.setTimeout(longish);
        try {
            collection.deleteItem(item);
        } catch (SecurityException e) {
            log.info("Unexpected SecurityException:", e);
        }
    }

    @Test
    public void close() throws IOException {
        SimpleCollection collection = new SimpleCollection();
        assertDoesNotThrow(() -> collection.close());
    }

    @Test
    public void isLocked() throws IOException {
        SimpleCollection collection = new SimpleCollection("test", "test");
        assertFalse(collection.isLocked());
        collection.delete();
    }

    @Test
    @Disabled("disconnect() affects the global static DBusConnection and cannot be undone within the static lifetime")
    public void disconnect() throws IOException {
        SimpleCollection collection = new SimpleCollection("test", "test");
        assertTrue(collection.isConnected());
        assertTrue(SimpleCollection.isConnected());

        // always false, as static methods cannot override interfaces.
        assertFalse(de.swiesend.secretservice.simple.interfaces.SimpleCollection.isConnected());
    }

    @Test
    @DisplayName("SimpleCollection.close() cleans up sessions but keeps the static D-Bus connection alive")
    public void closeKeepsStaticConnection() throws IOException {
        assertTrue(SimpleCollection.isConnected(), "Static connection should be alive before test");

        SimpleCollection collection = new SimpleCollection("test", "test");
        collection.close();

        // The static D-Bus connection is wrapped (non-owning) by the functional layer,
        // so closing the collection/service should NOT disconnect it.
        assertTrue(SimpleCollection.isConnected(),
                "Static D-Bus connection should remain alive after SimpleCollection.close()");
        assertTrue(SimpleCollection.isAvailable(),
                "Secret service should still be available after SimpleCollection.close()");
    }

    @Test
    @DisplayName("SimpleCollection can be reopened after close - sessions are independent")
    public void reopenAfterClose() throws IOException {
        SimpleCollection first = new SimpleCollection("test", "test");
        String item = first.createItem("reopen-test", "secret-value");
        first.close();

        // Open a new instance after closing the first — should work because the
        // static D-Bus connection is still alive
        SimpleCollection second = new SimpleCollection("test", "test");
        char[] secret = second.getSecret(item);
        assertArrayEquals("secret-value".toCharArray(), secret);
        Arrays.fill(secret, '\0');

        second.deleteItem(item);
        second.delete();
        second.close();
    }

    @Test
    @DisplayName("Multiple SimpleCollection instances share the same static D-Bus connection")
    public void multipleInstancesShareConnection() throws IOException {
        SimpleCollection col1 = new SimpleCollection("test", "test");
        SimpleCollection col2 = new SimpleCollection("test", "test");

        String item = col1.createItem("shared-test", "secret");
        // col2 can see it because they share the same D-Bus connection
        char[] secret = col2.getSecret(item);
        assertArrayEquals("secret".toCharArray(), secret);
        Arrays.fill(secret, '\0');

        col1.deleteItem(item);
        col1.delete();

        // Closing one doesn't affect the other's ability to operate
        col1.close();
        assertTrue(SimpleCollection.isConnected(),
                "Static connection should survive closing one instance");

        col2.close();
        assertTrue(SimpleCollection.isConnected(),
                "Static connection should survive closing all instances");
    }

}
