package org.freedesktop.secret.simple;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Example {

    /*
     * FIXME: [#4](https://github.com/swiesend/secret-service/issues/4)
     *     Running JUnit test for all in secret-service fails, whereas individually they pass.
     *     [main] INFO org.freedesktop.secret.handlers.SignalHandler - await signal org.freedesktop.secret.interfaces.Prompt$Completed(/org/freedesktop/secrets/prompt/u8) within 60 seconds.
     *     [main] ERROR org.freedesktop.secret.handlers.SignalHandler - java.util.concurrent.TimeoutException
     */
    @Test
    @Disabled
    @DisplayName("Create a password in the user's default collection.")
    public void createPasswordInDefaultCollection() {
        Optional<SimpleCollection> connection = new SimpleService().connect();
        if (connection.isPresent()) {
            try (SimpleCollection collection = connection.get()) {
                String item = collection.createItem("My Item", "secret");

                char[] actual = collection.getSecret(item);
                assertEquals("secret", new String(actual));
                assertEquals("My Item", collection.getLabel(item));

                collection.deleteItem(item);
            } // clears automatically all session secrets in memory
        }
    }

    @Test
    @DisplayName("Create a password in a non-default collection.")
    public void createPasswordInNonDefaultCollection() {
        Optional<SimpleCollection> connection = new SimpleService().connect("My Collection", "super secret");
        if (connection.isPresent()) {
            try (SimpleCollection collection = connection.get()) {
                String item = collection.createItem("My Item", "secret");

                char[] actual = collection.getSecret(item);
                assertEquals("secret", new String(actual));
                assertEquals("My Item", collection.getLabel(item));

                collection.deleteItem(item);
                collection.delete();
            } // clears automatically all session secrets in memory
        }
    }

    @Test
    @DisplayName("Create a password with additional attributes.")
    public void createPasswordWithAttributes() {
        Optional<SimpleCollection> connection = new SimpleService().connect("My Collection", "super secret");
        if (connection.isPresent()) {
            try (SimpleCollection collection = connection.get()) {
                // define unique attributes
                Map<String, String> attributes = new HashMap();
                attributes.put("uuid", "42");

                // create and forget
                collection.createItem("My Item", "secret", attributes);

                // find by attributes
                List<String> items = collection.getItems(attributes);
                assertEquals(1, items.size());
                String item = items.get(0);

                char[] actual = collection.getSecret(item);
                assertEquals("secret", new String(actual));
                assertEquals("My Item", collection.getLabel(item));
                assertEquals("42", collection.getAttributes(item).get("uuid"));

                collection.deleteItem(item);
                collection.delete();
            } // clears automatically all session secrets in memory
        }
    }
}
