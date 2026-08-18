package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Coverage for the secret-handling guarantees of the functional {@code Collection}:
 * {@code withSecret}/{@code withSecrets} zero their material after the callback, the
 * map handed to {@code withSecrets} is unmodifiable, and the various {@code Optional}
 * error paths (missing item, null callback result) return empty rather than throwing.
 */
class SecretCleanupTest {

    private ServiceInterface service;
    private SessionInterface session;
    private CollectionInterface collection;

    @BeforeEach
    void setUp() {
        service = SecretService.create().get();
        session = service.openSession().get();
        try {
            collection = session.collection("test-cleanup-collection", Optional.of("password")).get();
        } catch (NoSuchElementException e) {
            collection = session.collection("test-cleanup-collection", Optional.empty()).get();
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
    @DisplayName("getSecret on a non-existent item returns Optional.empty (no throw)")
    void getSecretMissingItemIsEmpty() {
        assertEquals(Optional.empty(),
                collection.getSecret("/org/freedesktop/secrets/collection/test_2dcleanup_2dcollection/does_not_exist"));
    }

    @Test
    @DisplayName("withSecret zeroes the char[] after the callback and propagates the result")
    void withSecretClearsAndReturns() {
        String item = collection.createItem("label", "topsecret").get();

        char[][] captured = new char[1][];
        Optional<Integer> length = collection.withSecret(item, chars -> {
            captured[0] = chars;
            assertArrayEquals("topsecret".toCharArray(), chars);
            return chars.length;
        });

        assertEquals(Optional.of("topsecret".length()), length);
        assertNotNull(captured[0]);
        assertArrayEquals(new char[captured[0].length], captured[0],
                "secret must be zeroed after withSecret returns");
    }

    @Test
    @DisplayName("withSecret still zeroes the char[] when the callback throws")
    void withSecretClearsOnException() {
        String item = collection.createItem("label", "boomsecret").get();

        char[][] captured = new char[1][];
        assertThrows(RuntimeException.class, () -> collection.withSecret(item, chars -> {
            captured[0] = chars;
            throw new RuntimeException("callback failure");
        }));

        assertNotNull(captured[0]);
        assertArrayEquals(new char[captured[0].length], captured[0],
                "secret must be zeroed even when the callback throws");
    }

    @Test
    @DisplayName("withSecret returning null yields Optional.empty")
    void withSecretNullResultIsEmpty() {
        String item = collection.createItem("label", "secret").get();
        assertEquals(Optional.empty(), collection.withSecret(item, chars -> null));
    }

    @Test
    @DisplayName("withSecrets hands the callback an unmodifiable map and zeroes the values afterwards")
    void withSecretsUnmodifiableAndCleared() {
        String item = collection.createItem("label", "multisecret").get();

        // The map must reject mutation.
        Optional<Boolean> rejectedMutation = collection.withSecrets(secrets -> {
            try {
                secrets.put("intruder", new char[]{'x'});
                return false;
            } catch (UnsupportedOperationException expected) {
                return true;
            }
        });
        assertEquals(Optional.of(Boolean.TRUE), rejectedMutation,
                "the map passed to withSecrets must be unmodifiable");

        // The values must be zeroed once the callback returns.
        char[][] captured = new char[1][];
        Optional<Boolean> found = collection.withSecrets(secrets -> {
            captured[0] = secrets.get(item);
            return secrets.values().stream().anyMatch(v -> Arrays.equals(v, "multisecret".toCharArray()));
        });
        assertEquals(Optional.of(Boolean.TRUE), found);
        assertNotNull(captured[0]);
        assertArrayEquals(new char[captured[0].length], captured[0],
                "secret values must be zeroed after withSecrets returns");
    }
}
