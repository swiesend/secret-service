package org.freedesktop.secret.simple;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.AccessControlException;
import java.time.Duration;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class SimpleCollectionTest {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollectionTest.class);

    private String getRandomHexString(int length) {
        Random r = new Random();
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length) {
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString();
    }

    @Test
    @Disabled("Danger Zone! Be aware that this can lead to the loss of passwords.")
    public void deleteDefaultCollection() throws IOException {
        SimpleCollection defaultCollection = new SimpleCollection();
        assertThrows(AccessControlException.class, defaultCollection::delete);
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
        assertEquals("sécrèt", new String(collection.getSecret(item)));
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

        Map<String, String> attributes = new HashMap();
        attributes.put("uuid", getRandomHexString(32));

        String item = collection.createItem("item", "secret", attributes);
        assertEquals("item", collection.getLabel(item));
        assertEquals("secret", new String(collection.getSecret(item)));
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
        Map<String, String> attributes = new HashMap();

        // create password
        attributes.put("uuid", getRandomHexString(32));
        log.info("attributes: " + attributes);

        String item = collection.createItem("item", "secret", attributes);
        assertEquals("item", collection.getLabel(item));
        assertEquals("secret", new String(collection.getSecret(item)));
        Map<String, String> actualAttributes = collection.getAttributes(item);
        assertEquals(attributes.get("uuid"), actualAttributes.get("uuid"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        }

        // update password
        attributes.put("uuid", getRandomHexString(32));
        log.info("attributes: " + attributes);
        collection.updateItem(item, "updated item", "updated secret", attributes);
        assertEquals("updated item", collection.getLabel(item));
        assertEquals("updated secret", new String(collection.getSecret(item)));
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
        Map<String, String> attributes = new HashMap();
        attributes.put("uuid", getRandomHexString(32));
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
        assertEquals("secret", new String(password));

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
        assertEquals("secret", new String(password));

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
        assertEquals("secret", new String(password));

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
        String item = collection.createItem("item", "secret");
        assertDoesNotThrow(() -> collection.deleteItems(Arrays.asList(item)));
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
    public void setTimeout() throws IOException, InterruptedException {
        SimpleCollection collection = new SimpleCollection();
        String item = collection.createItem("item", "secret");

        // wait 3 seconds before cancelling the prompt manually
        try {
            Duration kurz = Duration.ofSeconds(3);
            collection.setTimeout(kurz);
            Map<String, char[]> ignored = collection.getSecrets();
        } catch (AccessControlException e) {
            log.info(e.getMessage());
        }

        Duration lang = Duration.ofSeconds(120);
        collection.setTimeout(lang);
        collection.deleteItem(item);
    }
}
