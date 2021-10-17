package org.freedesktop.secret.integration;

import org.freedesktop.secret.simple.SimpleCollection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.AccessControlException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RegressionTests {

    @Test
    @DisplayName("Use two times an auto-close scope with a default collection")
    public void autoCloseTwice() throws IOException, AccessControlException, IllegalArgumentException {
        assertTrue(SimpleCollection.isAvailable());

        String item = "";

        try (SimpleCollection collection = new SimpleCollection("test", "test")) {
            if (!collection.isLocked()) {
                item = collection.createItem("Item", "secret");
            } else {
                assert false;
            }
        } // auto-close

        try (SimpleCollection collection = new SimpleCollection("test", "test")) {
            if (!collection.isLocked()) {
                char[] actual = collection.getSecret(item);
                assertEquals("secret", new String(actual));
                assertEquals("Item", collection.getLabel(item));
                collection.deleteItem(item);
            } else {
                assert false;
            }
        } // auto-close
    }

}
