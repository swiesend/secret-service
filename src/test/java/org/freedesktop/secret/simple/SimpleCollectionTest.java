package org.freedesktop.secret.simple;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    public void deleteDefaultCollection() {
        SimpleCollection defaultCollection = new SimpleCollection();
        assertThrows(AccessControlException.class, () -> defaultCollection.delete());
    }

    @Test
    public void deleteNonDefaultCollection() {
        SimpleCollection collection = new SimpleCollection("test", "test");
        assertDoesNotThrow(() -> collection.delete());
    }

    @Test
    public void createPasswordWithoutAttributes() {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");

        String item = collection.createPassword("item", "sécrèt");
        assertEquals("item", collection.getLabel(item));
        assertEquals("sécrèt", new String(collection.getPassword(item)));
        Map<String, String> actualAttributes = collection.getAttributes(item);
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        } else {
            assertEquals(Collections.emptyMap(), collection.getAttributes(item));
        }

        // after
        collection.deletePassword(item);
        collection.delete();
    }

    @Test
    public void createPasswordWithAttributes() {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");

        Map<String, String> attributes = new HashMap();
        attributes.put("uuid", getRandomHexString(32));

        String item = collection.createPassword("item", "secret", attributes);
        assertEquals("item", collection.getLabel(item));
        assertEquals("secret", new String(collection.getPassword(item)));
        Map<String, String> actualAttributes = collection.getAttributes(item);
        assertEquals(attributes.get("uuid"), actualAttributes.get("uuid"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        }

        // after
        collection.deletePassword(item);
        collection.delete();
    }

    @Test
    public void updatePassword() {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");
        Map<String, String> attributes = new HashMap();

        // create password
        attributes.put("uuid", getRandomHexString(32));
        log.info("attributes: " + attributes);

        String item = collection.createPassword("item", "secret", attributes);
        assertEquals("item", collection.getLabel(item));
        assertEquals("secret", new String(collection.getPassword(item)));
        Map<String, String> actualAttributes = collection.getAttributes(item);
        assertEquals(attributes.get("uuid"), actualAttributes.get("uuid"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        }

        // update password
        attributes.put("uuid", getRandomHexString(32));
        log.info("attributes: " + attributes);
        collection.updatePassword(item, "updated item", "updated secret", attributes);
        assertEquals("updated item", collection.getLabel(item));
        assertEquals("updated secret", new String(collection.getPassword(item)));
        actualAttributes = collection.getAttributes(item);
        assertEquals(attributes.get("uuid"), actualAttributes.get("uuid"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", collection.getAttributes(item).get("xdg:schema"));
        }

        // after
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
    public void getPasswordFromDefaultCollection() {
        // before
        SimpleCollection collection = new SimpleCollection();
        String item = collection.createPassword("item", "secret");

        // test
        char[] password = collection.getPassword(item);
        assertEquals("secret", new String(password));

        // after
        collection.deletePassword(item);
    }

    @Test
    public void getPasswordFromNonDefaultCollection() {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");
        String itemID = collection.createPassword("item", "secret");

        // test
        char[] password = collection.getPassword(itemID);
        assertEquals("secret", new String(password));

        // after
        collection.deletePassword(itemID);
        collection.delete();
    }

    @Test
    @Disabled
    public void getPasswords() {
        SimpleCollection collection = new SimpleCollection();
        assertDoesNotThrow(() -> {
            // only with user permission
            Map<String, char[]> passwords = collection.getPasswords();
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
    public void deletePassword() {
        SimpleCollection collection = new SimpleCollection();
        String item = collection.createPassword("item", "secret");
        assertDoesNotThrow(() -> {
            // only with user permission
            collection.deletePassword(item);
        });
    }

    /**
     * NOTE: Be aware that this can lead to the loss of passwords if performed on the default collection.
     */
    @Test
    public void deletePasswords() {
        SimpleCollection collection = new SimpleCollection("test", "test");
        String item = collection.createPassword("item", "secret");
        assertDoesNotThrow(() -> {
            collection.deletePasswords(Arrays.asList(item));
        });
        collection.delete();
    }
}
