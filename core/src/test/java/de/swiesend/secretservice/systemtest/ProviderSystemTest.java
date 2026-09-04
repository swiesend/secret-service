package de.swiesend.secretservice.systemtest;

import de.swiesend.secretservice.ProviderDetector;
import de.swiesend.secretservice.ProviderDetector.Provider;
import de.swiesend.secretservice.functional.SearchMode;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.System;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Provider-agnostic system test. Exercises the full CRUD + search flow of the
 * functional API against whichever provider currently serves
 * {@code org.freedesktop.secrets}:
 *
 * <ul>
 *   <li><b>gnome-keyring</b> — a {@code test} collection is created/opened by label.</li>
 *   <li><b>KeePassXC</b> — requires a running instance with Secret Service integration
 *       and a database exposing a group as collection id {@code test} (password {@code test}).</li>
 *   <li><b>KWallet (ksecretd)</b> — requires the modern KDE Secret Service daemon with a
 *       wallet/folder exposed as collection id {@code test}.</li>
 * </ul>
 *
 * <p>The suite uses {@link Assumptions} to skip cleanly when no provider/collection is
 * present, so it is safe to run anywhere. It is excluded from the default build; run with:
 * <pre>{@code mvn test -Psystem-test}</pre>
 */
@Tag("system-test")
public class ProviderSystemTest {

    private static final Logger log = LoggerFactory.getLogger(ProviderSystemTest.class);

    /** Collection id/label used across all providers. */
    static final String COLLECTION = "test";
    /** Password used when a provider lets us create/unlock the collection (gnome-keyring). */
    static final String COLLECTION_PASSWORD = "test";

    private SystemInterface system;
    private ServiceInterface service;
    private SessionInterface session;
    private CollectionInterface collection;
    /** Whether this test created the collection and may therefore delete it on teardown. */
    private boolean ownsCollection;

    @BeforeEach
    void setUp() {
        system = System.connect().orElse(null);
        Assumptions.assumeTrue(system != null, "Could not connect to D-Bus");

        Provider provider = ProviderDetector.detectProvider(system.getConnection());
        log.info("Running provider system test against: {}", provider);
        Assumptions.assumeTrue(provider != Provider.UNAVAILABLE,
                "No Secret Service provider available on the session bus");

        service = SecretService.create(Optional.of(system)).orElse(null);
        Assumptions.assumeTrue(service != null, "SecretService not available");

        session = service.openSession().orElse(null);
        Assumptions.assumeTrue(session != null, "Could not open session");

        collection = resolveTestCollection(session, provider);
        Assumptions.assumeTrue(collection != null,
                "Collection '" + COLLECTION + "' not available for provider " + provider);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (collection != null) {
            // Only delete the collection on providers where we created it (gnome-keyring).
            // On KeePassXC/KWallet the collection is a pre-existing user database.
            if (ownsCollection) {
                collection.delete();
            }
            collection.close();
        }
        if (session != null) session.close();
        if (service != null) service.close();
    }

    /**
     * Resolves a usable collection for the detected provider. gnome-keyring collections are
     * created/opened by label+password. KeePassXC and KWallet expose pre-existing
     * databases/wallets: we use the {@code test} collection when present, otherwise the first
     * exposed collection (e.g. KWallet's {@code kdewallet}), and return {@code null} when none
     * exists so the suite skips rather than failing on a non-existent object path.
     *
     * <p>{@code collectionById()} returns a wrapper even for a non-existent path, so existence
     * must be checked against the provider's real collection list.</p>
     */
    private CollectionInterface resolveTestCollection(SessionInterface session, Provider provider) {
        if (provider == Provider.GNOME_KEYRING) {
            CollectionInterface created =
                    session.collection(COLLECTION, Optional.of(COLLECTION_PASSWORD)).orElse(null);
            ownsCollection = created != null;
            return created;
        }

        List<String> existing = existingCollectionIds(session);
        String target = existing.contains(COLLECTION)
                ? COLLECTION
                : (existing.isEmpty() ? null : existing.get(0));
        if (target == null) {
            log.info("Provider {} exposes no collection - skipping", provider);
            return null;
        }
        log.info("Provider {} - using existing collection id '{}'", provider, target);
        ownsCollection = false; // pre-existing user database/wallet: never delete it
        return session.collectionById(target).orElse(null);
    }

    /** Last path segments of the collections actually exposed by the provider. */
    private List<String> existingCollectionIds(SessionInterface session) {
        return session.getService().getService().getCollections()
                .orElse(List.of()).stream()
                .map(p -> {
                    String path = p.getPath();
                    return path.substring(path.lastIndexOf('/') + 1);
                })
                .toList();
    }

    @Test
    @DisplayName("create, read, search and delete an item against the live provider")
    void crudRoundtrip() {
        String label = "provider-system-item";
        String secret = "s3cr3t-system";
        Map<String, String> attributes = Map.of("application", "secret-service-it", "kind", "system-test");

        // create
        String itemPath = collection.createItem(label, secret, attributes).orElse(null);
        assertNotNull(itemPath, "createItem returned empty");

        // read back the decrypted secret
        char[] got = collection.getSecret(itemPath).orElse(null);
        assertNotNull(got, "getSecret returned empty");
        assertArrayEquals(secret.toCharArray(), got);
        Arrays.fill(got, '\0');

        // attributes round-trip
        Map<String, String> storedAttrs = collection.getAttributes(itemPath).orElse(Map.of());
        assertEquals("secret-service-it", storedAttrs.get("application"));

        // the item is discoverable by name and by attribute value
        List<String> byName = collection.search(label, SearchMode.BY_NAME);
        assertTrue(byName.contains(itemPath), "item should be found by name");
        List<String> byAttr = collection.search("secret-service-it", SearchMode.BY_ATTRIBUTE_VALUE);
        assertTrue(byAttr.contains(itemPath), "item should be found by attribute value");

        // delete
        assertTrue(collection.deleteItem(itemPath), "could not delete created item");
        assertFalse(collection.search(label, SearchMode.BY_NAME).contains(itemPath),
                "item should be gone after deletion");
    }

    @Test
    @DisplayName("withSecret zeroes the secret after the callback returns")
    void withSecretClearsAfterCallback() {
        String label = "provider-system-with-secret";
        String secret = "callback-secret";
        String itemPath = collection.createItem(label, secret).orElse(null);
        assertNotNull(itemPath, "createItem returned empty");

        try {
            char[][] captured = new char[1][];
            Optional<Boolean> result = collection.withSecret(itemPath, chars -> {
                captured[0] = chars; // capture the live reference; the library zeroes it afterwards
                return Arrays.equals(secret.toCharArray(), chars);
            });
            assertEquals(Optional.of(Boolean.TRUE), result, "callback should observe the plaintext secret");
            assertNotNull(captured[0]);
            assertArrayEquals(new char[captured[0].length], captured[0],
                    "secret char[] must be zeroed after withSecret returns");
        } finally {
            collection.deleteItem(itemPath);
        }
    }

    @Test
    @DisplayName("a live provider that locks items individually can still be read (issue #45)")
    void perItemLockIsHandledAgainstTheLiveProvider() {
        // Honest about its coverage: this SKIPS on every provider in CI today. gnome-keyring never
        // locks a single item, and the KeePassXC container sets ConfirmAccessItem=false, which
        // switches the behaviour off. It is here so that a developer running against a real
        // KeePassXC with per-item confirmation enabled -- and CI, if that setting is ever turned on
        // -- exercises the real wire path. The deterministic coverage lives in PerItemUnlockTest,
        // which drives a fake provider that does lock items.
        // Deliberately not gated on a provider name. The condition below -- collection unlocked,
        // item locked -- is what the code under test reacts to, whoever produces it, and this suite
        // is provider-agnostic by design. Naming KeePassXC here would also skip a future KWallet
        // that grew the same behaviour.
        String label = "provider-system-per-item-lock";
        String secret = "s3cr3t-per-item";

        String itemPath = collection.createItem(label, secret, Map.of("kind", "system-test")).orElse(null);
        assertNotNull(itemPath, "createItem returned empty");
        try {
            // NOTHING here locks anything. An earlier version called lockItem() to manufacture the
            // condition, which is not safe against a live provider: KeePassXC's Lock on an item
            // locks the whole database, that database is the user's own, and the only way back is
            // unlockWithUserPermission() -- which locks and re-prompts, so in a headless run it
            // blocks until the prompt times out and then leaves the database locked anyway. Worse
            // than not trying.
            //
            // So the test observes rather than arranges: with per-item confirmation enabled, the
            // provider reports a freshly written item as locked on its own. That is the real
            // condition, and if it is not present there is nothing here to exercise.
            Assumptions.assumeTrue(!collection.isLocked() && lockedIndividually(itemPath),
                    "provider does not lock items individually; nothing to exercise here");

            char[] got = collection.getSecret(itemPath).orElse(null);
            assertNotNull(got, "a locked item must be unlocked automatically and then read");
            assertArrayEquals(secret.toCharArray(), got);
            Arrays.fill(got, '\0');
        } finally {
            collection.deleteItem(itemPath);
        }
    }

    /** Whether the provider really reports this one item as locked, as KeePassXC does. */
    private boolean lockedIndividually(String itemPath) {
        // Read the item's own Locked property -- the exact condition unlockItemIfLocked branches
        // on. An earlier version inferred it from getAttributes() failing, which is a different
        // question: the spec keeps locked items discoverable with their attributes, and KeePassXC
        // gates confirm-access on GetSecret rather than on the Attributes read. So on the one
        // provider this test targets, the item reported Locked while getAttributes succeeded, and
        // the test skipped while claiming to cover the live per-item path.
        return new de.swiesend.secretservice.Item(
                de.swiesend.secretservice.Static.Convert.toObjectPath(itemPath),
                service.getService()).isLocked();
    }
}
