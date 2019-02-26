package org.freedesktop.secret.simple;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Example {

    @Test
    @DisplayName("Create a password in the user's default collection ('/org/freedesktop/secrets/aliases/default').")
    public void createPasswordInDefaultCollection() {
        try (SimpleCollection collection = new SimpleCollection()) {
            String item = collection.createPassword("My Item", "secret");
            char[] actual = collection.getPassword(item);
            assertEquals("secret", new String(actual));
            assertEquals("My Item", collection.getLabel(item));

            // delete with a prompt, as the collection password is unknown.
            collection.deletePassword(item);
        } // clears the private key and session key afterwards
    }

    @Test
    @DisplayName("Create a password in a non-default collection ('/org/freedesktop/secrets/collection/xxxx').")
    public void createPasswordInNonDefaultCollection() {
        try (SimpleCollection collection = new SimpleCollection("My Collection", "super secret")) {
            String item = collection.createPassword("My Item", "secret");
            char[] actual = collection.getPassword(item);
            assertEquals("secret", new String(actual));
            assertEquals("My Item", collection.getLabel(item));

            // delete without prompting, as the collection password is known.
            collection.deletePassword(item);
            collection.delete();
        } // clears the collection's password, private key and session key afterwards
    }

    @Test
    @DisplayName("Create a password with additional attributes.")
    public void createPasswordWithAttributes() {
        try (SimpleCollection collection = new SimpleCollection("My Collection", "super secret")) {
            Map<String, String> attributes = new HashMap();
            attributes.put("uuid", "42");

            String item = collection.createPassword("My Item", "secret", attributes);
            char[] actual = collection.getPassword(item);
            assertEquals("secret", new String(actual));
            assertEquals("My Item", collection.getLabel(item));
            assertEquals("42", collection.getAttributes(item).get("uuid"));

            // delete without prompting, as the collection password is known.
            collection.deletePassword(item);
            collection.delete();
        } // clears the collection's password, private key and session key afterwards
    }
}
