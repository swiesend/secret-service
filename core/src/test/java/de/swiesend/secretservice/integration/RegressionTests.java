package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class RegressionTests {

    @Test
    @DisplayName("Use two times an auto-close scope with the same collection")
    public void autoCloseTwice() throws Exception {
        // The second scope must still reach what the first one wrote: closing a service, its
        // session and its collection must not leave anything behind that breaks the next one.
        String item;
        try (ServiceInterface service = SecretService.create().orElseThrow();
             SessionInterface session = service.openSession().orElseThrow();
             CollectionInterface collection = session.collection("test", Optional.of("test")).orElseThrow()) {
            assertFalse(collection.isLocked());
            item = collection.createItem("Item", "secret").orElseThrow();
        } // auto-close

        try (ServiceInterface service = SecretService.create().orElseThrow();
             SessionInterface session = service.openSession().orElseThrow();
             CollectionInterface collection = session.collection("test", Optional.of("test")).orElseThrow()) {
            assertFalse(collection.isLocked());
            assertEquals("secret", collection.withSecret(item, String::new).orElseThrow());
            assertEquals(Optional.of("Item"), collection.getItemLabel(item));
            collection.deleteItem(item);
        } // auto-close
    }

}
