package org.freedesktop.secret.simple;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.secret.interfaces.Item;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.AccessControlException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class SimpleCollectionTest {

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
    void deleteDefaultCollection() {
        SimpleCollection defaultCollection = new SimpleCollection();
        assertThrows(AccessControlException.class, () -> defaultCollection.delete());
    }

    @Test
    void deleteNonDefaultCollection() {
        SimpleCollection collection = new SimpleCollection("test", "test");
        assertDoesNotThrow(() -> collection.delete());
    }

    @Test
    void createPassword() {
        // before all
        SimpleCollection collection = new SimpleCollection("test", "test");

        DBusPath itemID;

        // 1. create and get password
        itemID = collection.createPassword("item", "secret");
        String actual = collection.getPassword(itemID);
        assertEquals("secret", actual);
        Item item = collection.getItem(itemID);
        assertEquals(Collections.emptyMap(), item.getAttributes());
        // after 1.
        collection.deletePassword(itemID);

        // 2. create and get attributes
        Map<String, String> attributes = new HashMap();
        String uuid = getRandomHexString(32);
        attributes.put("uuid", uuid);
        itemID = collection.createPassword("item", "secret", attributes);
        item = collection.getItem(itemID);
        Map<String, String> actualAttributes = item.getAttributes();
        assertEquals(attributes, actualAttributes);
        // after 2.
        collection.deletePassword(itemID);

        // after all
        collection.delete();
    }

    @Test
    void updatePassword() {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");
        Map<String, String> attributes = new HashMap();

        // create password
        attributes.put("uuid", getRandomHexString(32));
        DBusPath itemID = collection.createPassword("item", "secret", attributes);
        assertEquals("secret", collection.getPassword(itemID));
        Item item = collection.getItem(itemID);
        assertEquals("item", item.getLabel());
        assertEquals(attributes.get("uuid"), item.getAttributes().get("uuid"));

        // update password
        attributes.put("uuid", getRandomHexString(32));
        collection.updatePassword(itemID, "updated item", "updated secret", attributes);
        assertEquals("updated secret", collection.getPassword(itemID));
        item = collection.getItem(itemID);
        assertEquals("updated item", item.getLabel());
        assertEquals(attributes.get("uuid"), item.getAttributes().get("uuid"));

        // after
        collection.delete();
    }

    @Test
    void getPassword() {
        // before
        SimpleCollection collection = new SimpleCollection();
        DBusPath itemID = collection.createPassword("item", "secret");

        // test
        String password = collection.getPassword(itemID);
        assertEquals("secret", password);

        // after
        collection.deletePassword(itemID);
    }

    @Test
    void getPasswordFromNonDefaultCollection() {
        // before
        SimpleCollection collection = new SimpleCollection("test", "test");

        // test
        DBusPath item = collection.createPassword("item", "secret");
        String password = collection.getPassword(item);
        assertEquals("secret", password);

        // after
        collection.deletePassword(item);
        collection.delete();
    }

    @Test
    @Disabled
    void getPasswords() {
        SimpleCollection collection = new SimpleCollection();
        assertDoesNotThrow(() -> {
            // only with user permission
            Map<DBusPath, String> passwords = collection.getPasswords();
        });
    }

    @Test
    void deletePassword() {
        SimpleCollection collection = new SimpleCollection();
        DBusPath item = collection.createPassword("item", "secret");
        assertDoesNotThrow(() -> {
            // only with user permission
            collection.deletePassword(item);
        });
    }

    /**
     * NOTE: Be aware that this can lead to the loss of passwords if performed on any default collections.
     */
    @Test
    void deletePasswords() {
        SimpleCollection collection = new SimpleCollection("test", "test");
        DBusPath item = collection.createPassword("item", "secret");
        assertDoesNotThrow(() -> {
            collection.deletePasswords(Arrays.asList(item));
        });
        collection.delete();
    }

}