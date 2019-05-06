package org.freedesktop.secret.simple;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.AccessControlException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class SimpleCollectionTest {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollectionTest.class);

    private String getRandomHexString(int length) {
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while (sb.length() < length) {
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString();
    }

    @Test
    @Disabled
    public void deleteDefaultCollection() throws IOException {
        SimpleCollection defaultCollection = new SimpleCollection();
        assertThrows(AccessControlException.class, () -> defaultCollection.delete());
    }

    @Test
    public void deleteNonDefaultCollection() throws IOException {
        SimpleCollection collection = new SimpleCollection("test", "test");
        assertDoesNotThrow(() -> collection.delete());
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

    /*
     * FIXME: [#4](https://github.com/swiesend/secret-service/issues/4)
     *     Running JUnit test for all in secret-service fails, whereas individually they pass.
     *     [main] INFO org.freedesktop.secret.handlers.SignalHandler - await signal org.freedesktop.secret.interfaces.Prompt$Completed(/org/freedesktop/secrets/prompt/u8) within 60 seconds.
     *     [main] ERROR org.freedesktop.secret.handlers.SignalHandler - java.util.concurrent.TimeoutException
     */
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
    @Disabled
    public void getPasswords() throws IOException {
        SimpleCollection collection = new SimpleCollection();
        assertDoesNotThrow(() -> {
            // only with user permission
            Map<String, char[]> passwords = collection.getSecrets();
            assertNotNull(passwords);
        });
    }

    /*
     * FIXME: [#4](https://github.com/swiesend/secret-service/issues/4)
     *     Running JUnit test for all in secret-service fails, whereas individually they pass.
     *     [main] INFO org.freedesktop.secret.handlers.SignalHandler - await signal org.freedesktop.secret.interfaces.Prompt$Completed(/org/freedesktop/secrets/prompt/u8) within 60 seconds.
     *     [main] ERROR org.freedesktop.secret.handlers.SignalHandler - java.util.concurrent.TimeoutException
     */
    @Test
    @Disabled
    public void deletePassword() throws IOException {
        SimpleCollection collection = new SimpleCollection();
        String item = collection.createItem("item", "secret");
        assertDoesNotThrow(() -> {
            // only with user permission
            collection.deleteItem(item);
        });
    }

    /**
     * NOTE: Be aware that this can lead to the loss of passwords if performed on the default collection.
     */
    @Test
    public void deletePasswords() throws IOException {
        SimpleCollection collection = new SimpleCollection("test", "test");
        String item = collection.createItem("item", "secret");
        assertDoesNotThrow(() -> {
            collection.deleteItems(Arrays.asList(item));
        });
        collection.delete();
    }
}
