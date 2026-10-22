package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.integration.test.Dialogs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The functional API on the default collection, where reading all secrets and deleting an item ask
 * for the user's permission: the collection is locked and unlocked again through the provider's
 * dialog. On a desktop the default collection is the user's login keyring, so the tests run only
 * where someone answers the dialogs of a keyring of the run's own; see {@link Dialogs}.
 */
@EnabledIfSystemProperty(named = Dialogs.ANSWERED, matches = "true",
        disabledReason = "Locks the user's default collection, which only its password dialog unlocks again")
@EnabledIfSystemProperty(named = Dialogs.DEFAULT_COLLECTION, matches = "throwaway",
        disabledReason = Dialogs.NOT_A_THROWAWAY_KEYRING)
class DefaultCollectionTest {

    @Test
    void getSecretsReadsAllItemsAfterTheDialog() throws Exception {
        try (CollectionInterface collection = Collection.openDefault().get()) {
            String item = collection.createItem("item", "secret").get();
            try {
                Map<String, char[]> secrets = collection.getSecrets().get();
                assertArrayEquals("secret".toCharArray(), secrets.get(item));
                secrets.values().forEach(secret -> Arrays.fill(secret, '\0'));
            } finally {
                collection.deleteItem(item);
            }
        }
    }

    @Test
    void deleteItemDeletesAfterTheDialog() throws Exception {
        try (CollectionInterface collection = Collection.openDefault().get()) {
            String item = collection.createItem("item", "secret").get();
            char[] secret = collection.getSecret(item).get();
            assertArrayEquals("secret".toCharArray(), secret);
            Arrays.fill(secret, '\0');

            assertTrue(collection.deleteItem(item));
            assertTrue(collection.getSecret(item).isEmpty(), "the item is gone");
        }
    }
}
