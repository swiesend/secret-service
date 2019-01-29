package org.freedesktop.secret.simple;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.secret.interfaces.Item;
import org.junit.jupiter.api.*;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Example {

    @Test
    @DisplayName("Create a password in the user's default collection ('/org/freedesktop/secrets/aliases/default').")
    public void createPasswordInDefaultCollection() {
        SimpleCollection collection = new SimpleCollection();
        DBusPath itemID = collection.createPassword("My Item", "secret");
        String actual = collection.getPassword(itemID);
        assertEquals("secret", actual);

        // delete with user's permission trough a prompt, as password is unknown.
        collection.deletePassword(itemID);
    }

    @Test
    @DisplayName("Create a password in a non-default collection ('/org/freedesktop/secrets/collection/xxxx').")
    public void createPasswordInNonDefaultCollection() {
        SimpleCollection collection = new SimpleCollection("My Collection", "super secret");
        DBusPath itemID = collection.createPassword("My Item", "secret");
        String actual = collection.getPassword(itemID);
        assertEquals("secret", actual);

        // delete without prompting, as collection's password is known.
        collection.deletePassword(itemID);
        collection.delete();
    }

    @Test
    @DisplayName("Create a password with additional attributes.")
    public void createPasswordWithAttributes() {
        SimpleCollection collection = new SimpleCollection("My Collection", "super secret");

        Map<String, String> attributes = new HashMap();
        attributes.put("uuid", "42");

        DBusPath itemID = collection.createPassword("My Item", "secret", attributes);
        String actual = collection.getPassword(itemID);
        assertEquals("secret", actual);
        Item item = collection.getItem(itemID);
        assertEquals("42", item.getAttributes().get("uuid"));

        // delete without prompting, as collection's password is known.
        collection.deletePassword(itemID);
        collection.delete();
    }
}