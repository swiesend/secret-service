package org.freedesktop.secret.simple;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SimpleServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SimpleServiceTest.class);

    @Test
    public void connectToDefaultCollection() throws UnsupportedOperationException {

        assertDoesNotThrow(() -> new SimpleService().connect());

        Optional<SimpleCollection> connection = new SimpleService().connect();

        if (connection.isPresent()) {
            SimpleCollection collection = connection.get();
            assertNotNull(collection);
        } else {
            throw new UnsupportedOperationException("Could not establish a healthy D-Bus connection on this platform.");
        }
    }

    @Test
    public void connectToNonDefaultCollection() throws UnsupportedOperationException, InterruptedException {

        assertDoesNotThrow(() -> new SimpleService().connect("test", "test"));

        Optional<SimpleCollection> connection = new SimpleService().connect("test", "test");

        if (connection.isPresent()) {
            SimpleCollection collection = connection.get();
            assertNotNull(collection);
            collection.delete();
        } else {
            throw new UnsupportedOperationException("Could not establish a healthy D-Bus connection on this platform.");
        }

        Thread.sleep(250);
    }

}
