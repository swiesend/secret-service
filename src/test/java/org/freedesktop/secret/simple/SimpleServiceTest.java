package org.freedesktop.secret.simple;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SimpleServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SimpleServiceTest.class);

    @BeforeEach
    public void beforeEach() throws InterruptedException {
        Thread.sleep(50L);
    }

    @AfterEach
    public void afterEach() throws InterruptedException {
        Thread.sleep(50L);
    }

    @Test
    @Disabled
    public void connectToDefaultCollection() throws UnsupportedOperationException, InterruptedException, IOException {

        assertDoesNotThrow(() -> SimpleService.create());

        SimpleService service = SimpleService.create();
        try (SimpleSession collection = service.createSession()) {
            collection.openDefaultCollection();
            String item = collection.createItem("My Item", "secret").get();

            char[] actual = collection.getSecret(item);
            assertEquals("secret", new String(actual));
            assertEquals("My Item", collection.getLabel(item));

            collection.deleteItem(item);
        }

        Thread.sleep(250);
    }

    @Test
    public void connectToNonDefaultCollection() throws UnsupportedOperationException, InterruptedException, IOException {

        assertDoesNotThrow(() -> SimpleService.create());

        SimpleService service = SimpleService.create();
        try (SimpleSession collection = service.createSession()) {
            collection.openCollection("test", "test");
            String item = collection.createItem("My Item", "secret").get();

            char[] actual = collection.getSecret(item);
            assertEquals("secret", new String(actual));
            assertEquals("My Item", collection.getLabel(item));

            collection.deleteItem(item);
            collection.delete();
        }

        Thread.sleep(250);
    }

}
