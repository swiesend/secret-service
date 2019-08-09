package org.freedesktop.secret.simple;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SimpleServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SimpleServiceTest.class);

    @Test
    public void connectToDefaultCollection() throws UnsupportedOperationException, InterruptedException {

        assertDoesNotThrow(() -> new SimpleService().connect());

        Optional<SimpleCollection> connection = new SimpleService().connect();

        if (connection.isPresent()) {
            try (SimpleCollection collection = connection.get()) {
                String item = collection.createItem("My Item", "secret");

                char[] actual = collection.getSecret(item);
                assertEquals("secret", new String(actual));
                assertEquals("My Item", collection.getLabel(item));

                collection.deleteItem(item);
            }
        } else {
            throw new UnsupportedOperationException("Could not establish a healthy D-Bus connection on this platform.");
        }

        Thread.sleep(250);
    }

    @Test
    public void connectToNonDefaultCollection() throws UnsupportedOperationException, InterruptedException {

        assertDoesNotThrow(() -> new SimpleService().connect("test", "test"));

        Optional<SimpleCollection> connection = new SimpleService().connect("test", "test");

        if (connection.isPresent()) {
            try (SimpleCollection collection = connection.get()) {
                String item = collection.createItem("My Item", "secret");

                char[] actual = collection.getSecret(item);
                assertEquals("secret", new String(actual));
                assertEquals("My Item", collection.getLabel(item));

                collection.deleteItem(item);
                collection.delete();
            }
        } else {
            throw new UnsupportedOperationException("Could not establish a healthy D-Bus connection on this platform.");
        }

        Thread.sleep(250);
    }

}
