package de.swiesend.secretservice.systemtest;

import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Manual integration test: requires KeePassXC running with Secret Service integration enabled
 * and a database named "test.kdbx" (collection id "test", password "test").
 */
@Tag("system-test")
public class KeePassXCTest {

    static final String COLLECTION_ID = "test";

    @Test
    public void addAndReadItemInKeePassXC() throws Exception {
        // Ensure the service is creatable
        ServiceInterface service = SecretService.create().orElse(null);
        Assumptions.assumeTrue(service != null, "SecretService not available");

        SessionInterface session = service.openSession().orElse(null);
        Assumptions.assumeTrue(session != null, "Could not open session");

        // Try to open the collection by id 'test' (test.kdbx, password: test)
        CollectionInterface collection = session.collectionById(COLLECTION_ID).orElse(null);
        Assumptions.assumeTrue(collection != null, "Collection with id '" + COLLECTION_ID + "' not available");

        String label = "manual-test-item";
        String secret = "s3cr3t-manual";

        String itemPath = collection.createItem(label, secret, Map.of("manual", "true")).orElse(null);
        assertNotNull(itemPath, "createItem returned empty");

        char[] got = collection.getSecret(itemPath).orElse(null);
        assertNotNull(got, "getSecret returned empty");
        assertArrayEquals(secret.toCharArray(), got);

        // cleanup
        boolean deleted = collection.deleteItem(itemPath);
        assertTrue(deleted, "Could not delete created item");

        // close
        collection.close();
        session.close();
        service.close();
    }
}
