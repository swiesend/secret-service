package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.functional.SearchMode;
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
            assertArrayEquals(i.toCharArray(), secret);
            Arrays.fill(secret, '\0');
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
            assertArrayEquals(i.toCharArray(), secret);
            Arrays.fill(secret, '\0');

            Map<String, String> actualAttributes = collection.getAttributes(item).get();
            for (Map.Entry<String, String> entry : actualAttributes.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                log.info(key + ": " + value);
            }
            // Providers may keep additional internal attributes (e.g. gnome-keyring
            // injects "xdg:schema"=org.freedesktop.Secret.Generic), so the stored set must
            // *contain* the expected attributes rather than match its size exactly.
            assertTrue(actualAttributes.entrySet().containsAll(expectedAttributes.entrySet()),
                    () -> "expected " + expectedAttributes + " to be contained in " + actualAttributes);
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

        // gnome-keyring injects a default "xdg:schema"=org.freedesktop.Secret.Generic attribute,
        // and does so asynchronously -- so it may or may not be present by the time getAttributes
        // returns right after createItem. Comparing the raw map is therefore racy (this test used
        // to flake ~1 run in 10). Assert on the user-defined attributes only, ignoring any
        // provider-injected bookkeeping keys, so the result is deterministic. This mirrors how
        // createItemWithAttribute() and getItems() already tolerate xdg:schema.

        item = collection.createItem("test", "secret").get();
        maybeAttributes = collection.getAttributes(item);
        assertTrue(maybeAttributes.isPresent());
        assertEquals(emptyMap, userAttributes(maybeAttributes.get()));

        Map<String, String> attributes = Map.of("key", "value");
        item = collection.createItem("test", "secret", attributes).get();
        maybeAttributes = collection.getAttributes(item);
        assertTrue(maybeAttributes.isPresent());
        assertEquals(attributes, userAttributes(maybeAttributes.get()));
    }

    /**
     * Strips provider-injected bookkeeping attributes (e.g. gnome-keyring's asynchronously added
     * "xdg:schema") so a test can assert on exactly the attributes the caller set.
     */
    private static Map<String, String> userAttributes(Map<String, String> attributes) {
        Map<String, String> userDefined = new HashMap<>(attributes);
        userDefined.remove("xdg:schema");
        return userDefined;
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
        Optional<Boolean> result = collection.withSecret(item, secret -> {
            return Arrays.equals(secret, "secret-1".toCharArray());
        });
        assertTrue(result.isPresent());
        assertTrue(result.get());
    }

    @Test
    void withSecretClearsAfterCallback() {
        String item = collection.createItem("item-1", "secret-1").get();

        // Capture a reference to the char[] from inside the callback
        char[][] holder = new char[1][];
        Optional<Boolean> result = collection.withSecret(item, secret -> {
            holder[0] = secret;
            // secret is valid here
            assertTrue(Arrays.equals(secret, "secret-1".toCharArray()));
            return true;
        });

        assertTrue(result.isPresent(), "withSecret should have returned a result");
        assertNotNull(holder[0], "Callback should have captured the secret array");

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

        assertNotNull(holder[0], "Callback should have captured the secret array before throwing");

        // Even after an exception, the array should be zeroed
        for (char c : holder[0]) {
            assertEquals('\0', c, "Secret bytes should be zeroed even when callback throws");
        }
    }

    @Test
    void withSecretReturnsEmptyForMissingItem() {
        Optional<Boolean> result = collection.withSecret("/nonexistent/path", secret -> {
            return true;
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

    // ── search ────────────────────────────────────────────────────

    @Test
    void searchByNameSubstring() {
        String path = collection.createItem("apple-secret", "s").get();
        List<String> results = collection.search("apple", SearchMode.BY_NAME);
        assertTrue(results.contains(path), "Expected path in results for 'apple' substring");
        collection.deleteItem(path);
    }

    @Test
    void searchByNameSubstringCaseInsensitive() {
        String path = collection.createItem("MyBananaEntry", "s").get();
        List<String> results = collection.search("banana", SearchMode.BY_NAME);
        assertTrue(results.contains(path), "Expected case-insensitive match");
        collection.deleteItem(path);
    }

    @Test
    void searchByNameNoMatch() {
        String path = collection.createItem("orange-secret", "s").get();
        List<String> results = collection.search("zzz-no-match", SearchMode.BY_NAME);
        assertFalse(results.contains(path));
        collection.deleteItem(path);
    }

    @Test
    void searchEmptyQueryReturnsAll() {
        String p1 = collection.createItem("item-one", "1").get();
        String p2 = collection.createItem("item-two", "2").get();
        List<String> results = collection.search("", SearchMode.BY_NAME);
        assertTrue(results.contains(p1));
        assertTrue(results.contains(p2));
        collection.deleteItem(p1);
        collection.deleteItem(p2);
    }

    @Test
    void searchByAttributeKey() {
        String path = collection.createItem("attr-key-test", "s", Map.of("myapp-uuid", "1234")).get();
        List<String> results = collection.search("myapp", SearchMode.BY_ATTRIBUTE_KEY);
        assertTrue(results.contains(path));
        collection.deleteItem(path);
    }

    @Test
    void searchByAttributeValue() {
        String path = collection.createItem("attr-val-test", "s", Map.of("app", "my-application")).get();
        List<String> results = collection.search("my-application", SearchMode.BY_ATTRIBUTE_VALUE);
        assertTrue(results.contains(path));
        collection.deleteItem(path);
    }

    @Test
    void searchByObjectPath() {
        String path = collection.createItem("path-test", "s").get();
        // Last segment is the object id; search the full path
        String segment = path.substring(path.lastIndexOf('/') + 1);
        List<String> results = collection.search(segment, SearchMode.BY_OBJECT_PATH);
        assertTrue(results.contains(path));
        collection.deleteItem(path);
    }

    @Test
    void searchByObjectId() {
        String path = collection.createItem("id-test", "s").get();
        String id = path.substring(path.lastIndexOf('/') + 1);
        // Search using the last few chars of the id
        String suffix = id.substring(Math.max(0, id.length() - 4));
        List<String> results = collection.search(suffix, SearchMode.BY_OBJECT_ID);
        assertTrue(results.contains(path));
        collection.deleteItem(path);
    }

    @Test
    void searchFuzzyByNameFindsTypo() {
        String path = collection.createItem("grapefrut", "s").get(); // missing 'i'
        List<String> results = collection.search("grapefruit", SearchMode.BY_NAME, 2);
        assertTrue(results.contains(path), "Fuzzy search should match 1-edit-away label");
        collection.deleteItem(path);
    }

    @Test
    void searchFuzzyByObjectIdSuffix() {
        String path = collection.createItem("fuzzy-id-item", "s").get();
        String id = path.substring(path.lastIndexOf('/') + 1);
        // Take last 4 chars and introduce 1 typo
        String suffix = id.substring(Math.max(0, id.length() - 4));
        char[] chars = suffix.toCharArray();
        chars[0] = (chars[0] == 'a') ? 'b' : 'a'; // flip one character
        String fuzzyQuery = new String(chars);
        List<String> results = collection.search(fuzzyQuery, SearchMode.BY_OBJECT_ID, 2);
        assertTrue(results.contains(path), "Fuzzy search with maxDistance=2 should tolerate 1 typo");
        collection.deleteItem(path);
    }

    @Test
    void searchFuzzyMaxDistanceZeroFallsBackToSubstring() {
        String path = collection.createItem("mango-item", "s").get();
        List<String> resultsSubstring = collection.search("mango", SearchMode.BY_NAME, 0);
        List<String> resultsDirect   = collection.search("mango", SearchMode.BY_NAME);
        assertEquals(resultsDirect.contains(path), resultsSubstring.contains(path));
        collection.deleteItem(path);
    }
}