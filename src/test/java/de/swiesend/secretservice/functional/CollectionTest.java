package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class CollectionTest {

    private static final Logger log = LoggerFactory.getLogger(CollectionTest.class);

    ServiceInterface service = null;

    SessionInterface session = null;

    CollectionInterface collection = null;

    @BeforeEach
    void setUp() {
        service = SecretService.create().get();
        session = service.openSession().get();
        try {
            collection = session.collection("test-collection", Optional.of("password")).get();
        } catch (NoSuchElementException e) {
            collection = session.collection("test-collection", Optional.empty()).get();
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        collection.delete();
        collection.close();
        session.close();
        service.close();
    }

    @Test
    void clear() {
        assertTrue(collection.clear());
    }

    @Test
    void createItem() {
        for (String i : Arrays.asList("a", "b", "c")) {
            String item = collection.createItem(i, i).get();
            assertTrue(item.startsWith("/org/freedesktop/secrets/collection/test_2dcollection/"));
            String label = collection.getItemLabel(item).get();
            assertEquals(i, label);
            char[] secret = collection.getSecret(item).get();
            assertEquals(i, new String(secret));
        }
    }

    @Test
    void createItemWithAttribute() {
        for (String i : Arrays.asList("a", "b", "c")) {
            Map<String, String> expectedAttributes = Map.of(i, i, i + i, i + i);
            String item = collection.createItem(i, i, expectedAttributes).get();
            assertTrue(item.startsWith("/org/freedesktop/secrets/collection/test_2dcollection/"));

            String label = collection.getItemLabel(item).get();
            assertEquals(i, label);

            char[] secret = collection.getSecret(item).get();
            assertEquals(i, new String(secret));

            Map<String, String> actualAttributes = collection.getAttributes(item).get();
            for (Map.Entry<String, String> entry : actualAttributes.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                log.info(key + ": " + value);
            }
            assertEquals(expectedAttributes.size(), actualAttributes.size());
            for (Map.Entry<String, String> entry : expectedAttributes.entrySet()) {
                String key = entry.getKey();
                String expectedValue = entry.getValue();
                String actualValue = actualAttributes.get(key);
                assertEquals(expectedValue, actualValue);
            }
        }
    }

    @Test
    void delete() {
        assertTrue(collection.delete());
    }

    @Test
    void deleteALockedCollection() {
        assertTrue(collection.lock());
        assertTrue(collection.delete());
    }

    @Test
    void deleteWithALockedService() {
        assertTrue(service.getService().lockService());
        assertTrue(collection.delete());
    }

    @Test
    @Disabled("Requires interactive prompt dismissal to test password abort")
    void deleteCollectionWithoutPassword() {
        CollectionInterface collectionWithoutPassword = service.openSession().flatMap(session ->
                session.collection("test-no-password-collection", Optional.empty())
        ).get();
        // collectionWithoutPassword.disablePrompt();
        Optional<Map<String, char[]>> maybeSecrets = collectionWithoutPassword.getSecrets();
        // assertTrue(maybeSecrets.isEmpty());
        assertTrue(collectionWithoutPassword.delete());
    }

    @Test
    void deleteItem() {
        String item = null;
        item = collection.createItem("test", "secret").get();
        assertTrue(collection.deleteItem(item));
        assertTrue(collection.getSecret(item).isEmpty());

        Map<String, String> attributes = Map.of("key", "value");
        item = collection.createItem("test", "secret", attributes).get();
        assertTrue(collection.deleteItem(item));
        assertTrue(collection.getSecret(item).isEmpty());
    }

    @Test
    void deleteItems() {
        String item1 = collection.createItem("test", "secret1").get();
        String item2 = collection.createItem("test", "secret2").get();
        assertTrue(collection.deleteItems(List.of(item1, item2)));
        assertTrue(collection.getSecret(item1).isEmpty());
        assertTrue(collection.getSecret(item2).isEmpty());
    }

    @Test
    void getAttributes() {
        String item = null;
        Optional<Map<String, String>> maybeAttributes;
        Map<String, String> emptyMap = Map.of();
        ;

        item = collection.createItem("test", "secret").get();
        maybeAttributes = collection.getAttributes(item);
        assertTrue(maybeAttributes.isPresent());
        assertEquals(emptyMap, maybeAttributes.get());

        Map<String, String> attributes = Map.of("key", "value");
        item = collection.createItem("test", "secret", attributes).get();
        maybeAttributes = collection.getAttributes(item);
        assertTrue(maybeAttributes.isPresent());
        assertEquals(attributes, maybeAttributes.get());
    }

    @Test
    void getItems() throws InterruptedException {
        Map<String, String> attributes = Map.of("key", "value-1");
        String item1 = collection.createItem("item-1", "secret", attributes).get();
        String item2 = collection.createItem("item-2", "secret", Map.of("key", "value-2")).get();
        String item3 = collection.createItem("item-3", "secret", attributes).get();
        Optional<List<String>> maybeItems = collection.getItems(attributes);
        assertTrue(maybeItems.isPresent());
        List<String> items = maybeItems.get();
        assertEquals(2, items.size());
    }

    @Test
    void getItemLabel() {
        String item = collection.createItem("item-1", "secret").get();
        Optional<String> maybeLabel = collection.getItemLabel(item);
        assertTrue(maybeLabel.isPresent());
        assertEquals("item-1", maybeLabel.get());
    }

    @Test
    void setItemLabel() {
        String item = collection.createItem("item-original", "secret").get();
        assertTrue(collection.setItemLabel(item, "item-override"));
        Optional<String> maybeLabel = collection.getItemLabel(item);
        assertTrue(maybeLabel.isPresent());
        assertEquals("item-override", maybeLabel.get());
    }

    @Test
    void setLabel() {
        assertEquals("test-collection", collection.getLabel().get());
        assertTrue(collection.setLabel("override"));
        assertEquals("override", collection.getLabel().get());
    }

    @Test
    void getLabel() {
        assertEquals("test-collection", collection.getLabel().get());
    }

    @Test
    void getId() {
        assertEquals("test_2dcollection", collection.getId().get());
    }

    @Test
    void getSecret() {
        String item1 = collection.createItem("item-1", "secret-1").get();
        String item2 = collection.createItem("item-2", "secret-2").get();

        Optional<char[]> maybeSecret2 = collection.getSecret(item2);
        assertTrue(maybeSecret2.isPresent());
        assertEquals("secret-2", new String(maybeSecret2.get()));

        Optional<char[]> maybeSecret1 = collection.getSecret(item1);
        assertTrue(maybeSecret1.isPresent());
        assertEquals("secret-1", new String(maybeSecret1.get()));
    }

    @Test
    void withSecret() {
        String item = collection.createItem("item-1", "secret-1").get();

        // Use the secret within the callback -- it is auto-cleared after
        Optional<String> result = collection.withSecret(item, secret -> {
            return new String(secret);
        });
        assertTrue(result.isPresent());
        assertEquals("secret-1", result.get());
    }

    @Test
    void withSecretClearsAfterCallback() {
        String item = collection.createItem("item-1", "secret-1").get();

        // Capture a reference to the char[] from inside the callback
        char[][] holder = new char[1][];
        collection.withSecret(item, secret -> {
            holder[0] = secret;
            // secret is valid here
            assertEquals("secret-1", new String(secret));
            return true;
        });

        // After the callback, the array should be zeroed
        for (char c : holder[0]) {
            assertEquals('\0', c, "Secret bytes should be zeroed after withSecret callback");
        }
    }

    @Test
    void withSecretClearsOnException() {
        String item = collection.createItem("item-1", "secret-1").get();

        char[][] holder = new char[1][];
        try {
            collection.withSecret(item, secret -> {
                holder[0] = secret;
                throw new RuntimeException("simulated failure");
            });
        } catch (RuntimeException expected) {
            // expected
        }

        // Even after an exception, the array should be zeroed
        for (char c : holder[0]) {
            assertEquals('\0', c, "Secret bytes should be zeroed even when callback throws");
        }
    }

    @Test
    void withSecretReturnsEmptyForMissingItem() {
        Optional<String> result = collection.withSecret("/nonexistent/path", secret -> {
            return new String(secret);
        });
        assertTrue(result.isEmpty());
    }

    @Test
    void withSecretWrappingThirdPartyDigest() throws NoSuchAlgorithmException {
        // Example: wrapping a java.security.MessageDigest call inside the callback
        // as input while avoiding creation of an intermediate String.
        String item = collection.createItem("api-key", "my-secret-api-key").get();

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        Optional<byte[]> hash = collection.withSecret(item, secret -> {
            // Encode the secret directly to bytes, hash it, then return the hash.
            // The original char[] secret is auto-cleared after this callback returns,
            // and the temporary byte buffers are cleared in the finally block below.
            // Note: avoid new String(secret) here — String is immutable and cannot be
            // cleared, which would defeat the in-memory clearing benefit of withSecret().
            java.nio.ByteBuffer encodedSecret = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(secret));
            byte[] secretBytes = new byte[encodedSecret.remaining()];
            encodedSecret.get(secretBytes);
            try {
                return md.digest(secretBytes);
            } finally {
                Arrays.fill(secretBytes, (byte) 0);
                if (encodedSecret.hasArray()) {
                    Arrays.fill(encodedSecret.array(), (byte) 0);
                }
            }
        });

        assertTrue(hash.isPresent());
        assertEquals(32, hash.get().length); // SHA-256 produces 32 bytes
    }

    @Test
    void withSecretWrappingStringComparison() {
        // Example: comparing a stored secret against a user-provided password.
        // The secret never escapes the callback -- only the boolean result does.
        String item = collection.createItem("login", "correct-password").get();

        Optional<Boolean> matches = collection.withSecret(item, secret -> {
            return Arrays.equals(secret, "correct-password".toCharArray());
        });

        assertTrue(matches.isPresent());
        assertTrue(matches.get());

        Optional<Boolean> noMatch = collection.withSecret(item, secret -> {
            return Arrays.equals(secret, "wrong-password".toCharArray());
        });

        assertTrue(noMatch.isPresent());
        assertFalse(noMatch.get());
    }

    @Test
    void getSecrets() {
        Map<String, String> attributes = Map.of("key", "value-1");
        String item1 = collection.createItem("item-1", "secret-1", attributes).get();
        String item2 = collection.createItem("item-2", "secret-2", Map.of("key", "value-2")).get();
        String item3 = collection.createItem("item-3", "secret-3", attributes).get();
        Optional<Map<String, char[]>> maybeSecrets = collection.getSecrets();
        assertTrue(maybeSecrets.isPresent());
        assertEquals(3, maybeSecrets.get().size());
        assertEquals(Map.of(
                item1, "secret-1",
                item2, "secret-2",
                item3, "secret-3"
        ), maybeSecrets.map(m -> m
                .entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> String.valueOf(e.getValue())
                ))
        ).get());
    }

    @Test
    void isLocked() {
        String item1 = collection.createItem("item-1", "secret-1").get();

        assertTrue(!collection.isLocked());
        assertTrue(collection.lock());
        assertTrue(collection.isLocked());

        Optional<char[]> maybeItem1 = collection.getSecret(item1);
        assertTrue(maybeItem1.isPresent());
        assertTrue(!collection.isLocked());
    }

    @Test
    void lock() {
        assertTrue(collection.lock());
        assertTrue(collection.isLocked());
    }

    @Test
    void unlockWithUserPermission() {
        collection.lock();
        assertTrue(collection.unlockWithUserPermission());
        assertTrue(!collection.isLocked());
    }

    @Test
    void updateItem() {
        Map<String, String> attributes = Map.of("key", "value-1");
        String item1 = collection.createItem("item-1", "secret-1", attributes).get();

        Map<String, String> attributesOverride = Map.of("key", "value-override");
        assertTrue(collection.updateItem(item1, "item-1-override", "secret-1-override", attributesOverride));
        assertEquals(0, collection.getItems(attributes).get().size());
        List<String> updatedItems = collection.getItems(attributesOverride).get();
        assertEquals(1, updatedItems.size());
        assertEquals(item1, updatedItems.get(0));
        assertEquals("item-1-override", collection.getItemLabel(item1).get());
        assertEquals("secret-1-override", new String(collection.getSecret(item1).get()));
        Map<String, String> actualAttributes = collection.getAttributes(item1).get();
        assertEquals("value-override", actualAttributes.get("key"));
        if (actualAttributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", actualAttributes.get("xdg:schema"));
        }
    }

    @Test
    void close() throws Exception {
        collection.close();
        assertTrue(collection.lock());
        collection.disablePrompt();
        assertTrue(!collection.unlockWithUserPermission());
        collection.enablePrompt();
    }
}