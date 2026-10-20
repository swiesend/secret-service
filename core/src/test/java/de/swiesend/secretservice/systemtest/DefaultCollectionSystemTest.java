package de.swiesend.secretservice.systemtest;

import de.swiesend.secretservice.functional.Collection;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.integration.test.Dialogs;
import de.swiesend.secretservice.simple.SimpleCollection;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The default collection as Cryptomator uses it. Its GNOME Keyring backend,
 * {@code GnomeKeyringKeychainAccess} in
 * <a href="https://github.com/cryptomator/integrations-linux">cryptomator/integrations-linux</a>,
 * keeps the passphrase of each vault there through {@link SimpleCollection}: it stores, loads,
 * changes and deletes it, and opens the default collection anew for each call. The test makes
 * those calls, and the same calls through the functional API, which stays when 4.0 removes
 * {@code SimpleCollection}.
 *
 * <p>Deleting asks for the user's permission through the provider's unlock dialog, and every call
 * reads or writes the default collection, on a desktop the user's login keyring. So the test runs
 * only where someone answers the dialogs of a keyring of the run's own, as in the
 * gnome-keyring-dialogs leg; see {@link Dialogs}.</p>
 */
@Tag("system-test")
@EnabledIfSystemProperty(named = Dialogs.ANSWERED, matches = "true",
        disabledReason = "Deletes from the default collection through the unlock dialog, which needs a user")
@EnabledIfSystemProperty(named = Dialogs.DEFAULT_COLLECTION, matches = "throwaway",
        disabledReason = Dialogs.NOT_A_THROWAWAY_KEYRING)
class DefaultCollectionSystemTest {

    /** The label that Cryptomator gives each item. */
    private static final String LABEL = "Cryptomator";

    @Test
    @DisplayName("Cryptomator's calls through SimpleCollection store, load, change and delete a passphrase")
    void throughSimpleCollection() throws Exception {
        // Cryptomator uses this backend only where gnome-keyring serves the Secret Service.
        Assumptions.assumeTrue(SimpleCollection.isGnomeKeyringAvailable(),
                "gnome-keyring does not serve the Secret Service");
        storeLoadChangeAndDelete(new SimpleCollectionKeychain());
    }

    @Test
    @DisplayName("the same calls through the functional API store, load, change and delete a passphrase")
    void throughTheFunctionalApi() throws Exception {
        storeLoadChangeAndDelete(new FunctionalKeychain());
    }

    private static void storeLoadChangeAndDelete(Keychain keychain) throws Exception {
        String vault = "secret-service-system-test-" + UUID.randomUUID();

        assertFalse(keychain.isLocked(), "the default collection is unlocked");
        assertNull(keychain.load(vault), "no passphrase before it is stored");

        keychain.store(vault, "p0ssw0rd");
        assertEquals("p0ssw0rd", keychain.load(vault));

        // Cryptomator stores the passphrase of a vault that it knows by changing it.
        keychain.store(vault, "n3w-p0ssw0rd");
        assertEquals("n3w-p0ssw0rd", keychain.load(vault));

        keychain.change(vault, "ch4ng3d-p0ssw0rd");
        assertEquals("ch4ng3d-p0ssw0rd", keychain.load(vault));

        keychain.delete(vault);
        assertNull(keychain.load(vault), "no passphrase after it is deleted");
    }

    /** Cryptomator finds the item of a vault by the vault's id. */
    private static Map<String, String> attributes(String vault) {
        return Map.of("Vault", vault);
    }

    /** The passphrase, which the caller only compares, with the chars erased. */
    private static String read(char[] passphrase) {
        if (passphrase == null) return null;
        String read = new String(passphrase);
        Arrays.fill(passphrase, '\0');
        return read;
    }

    /** The calls of Cryptomator's backend, each on the default collection, opened anew. */
    private interface Keychain {

        boolean isLocked() throws Exception;

        void store(String vault, CharSequence passphrase) throws Exception;

        /** The passphrase, or null if the vault has none. */
        String load(String vault) throws Exception;

        void change(String vault, CharSequence passphrase) throws Exception;

        void delete(String vault) throws Exception;
    }

    /** {@code GnomeKeyringKeychainAccess} as integrations-linux has it, without its error handling. */
    private static final class SimpleCollectionKeychain implements Keychain {

        @Override
        public boolean isLocked() throws Exception {
            try (SimpleCollection keyring = new SimpleCollection()) {
                return keyring.isLocked();
            }
        }

        @Override
        public void store(String vault, CharSequence passphrase) throws Exception {
            try (SimpleCollection keyring = new SimpleCollection()) {
                List<String> list = keyring.getItems(attributes(vault));
                if (list == null || list.isEmpty()) {
                    keyring.createItem(LABEL, passphrase, attributes(vault));
                } else {
                    change(vault, passphrase);
                }
            }
        }

        @Override
        public String load(String vault) throws Exception {
            try (SimpleCollection keyring = new SimpleCollection()) {
                List<String> list = keyring.getItems(attributes(vault));
                if (list != null && !list.isEmpty()) {
                    return read(keyring.getSecret(list.get(0)));
                } else {
                    return null;
                }
            }
        }

        @Override
        public void change(String vault, CharSequence passphrase) throws Exception {
            try (SimpleCollection keyring = new SimpleCollection()) {
                List<String> list = keyring.getItems(attributes(vault));
                if (list != null && !list.isEmpty()) {
                    keyring.updateItem(list.get(0), LABEL, passphrase, attributes(vault));
                }
            }
        }

        @Override
        public void delete(String vault) throws Exception {
            try (SimpleCollection keyring = new SimpleCollection()) {
                List<String> list = keyring.getItems(attributes(vault));
                if (list != null && !list.isEmpty()) {
                    keyring.deleteItem(list.get(0));
                }
            }
        }
    }

    /** The same calls through the functional API, failing where it reports a failure. */
    private static final class FunctionalKeychain implements Keychain {

        private static CollectionInterface open() {
            return Collection.openDefault().orElseThrow(() -> new AssertionError("the default collection did not open"));
        }

        private static List<String> items(CollectionInterface keyring, String vault) {
            return keyring.getItems(attributes(vault)).orElseThrow(() -> new AssertionError("getItems failed"));
        }

        @Override
        public boolean isLocked() throws Exception {
            try (CollectionInterface keyring = open()) {
                return keyring.isLocked();
            }
        }

        @Override
        public void store(String vault, CharSequence passphrase) throws Exception {
            try (CollectionInterface keyring = open()) {
                if (items(keyring, vault).isEmpty()) {
                    assertTrue(keyring.createItem(LABEL, passphrase, attributes(vault)).isPresent(), "createItem");
                } else {
                    change(vault, passphrase);
                }
            }
        }

        @Override
        public String load(String vault) throws Exception {
            try (CollectionInterface keyring = open()) {
                List<String> items = items(keyring, vault);
                if (items.isEmpty()) return null;
                return read(keyring.getSecret(items.get(0)).orElseThrow(() -> new AssertionError("getSecret failed")));
            }
        }

        @Override
        public void change(String vault, CharSequence passphrase) throws Exception {
            try (CollectionInterface keyring = open()) {
                List<String> items = items(keyring, vault);
                assertFalse(items.isEmpty(), "the vault has an item");
                assertTrue(keyring.updateItem(items.get(0), LABEL, passphrase, attributes(vault)), "updateItem");
            }
        }

        @Override
        public void delete(String vault) throws Exception {
            try (CollectionInterface keyring = open()) {
                List<String> items = items(keyring, vault);
                assertFalse(items.isEmpty(), "the vault has an item");
                assertTrue(keyring.deleteItem(items.get(0)), "deleteItem");
            }
        }
    }
}
