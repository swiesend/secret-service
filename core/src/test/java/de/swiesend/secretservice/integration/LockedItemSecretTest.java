package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The secret of a locked item cannot be read. gnome-keyring and KeePassXC answer such a read with
 * an error, but KWallet answers with an empty secret (KDE bug 524650), which the library passed on
 * as the item's secret: after an unlock that the user refused, the item's password was empty.
 *
 * <p>Against {@link FakeSecretService}, with KWallet's bug reproduced.</p>
 */
class LockedItemSecretTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    /** A locked collection that stays locked, as when the user refuses to unlock it. */
    private CollectionInterface refusedUnlock() throws Exception {
        CollectionInterface collection = harness.start(false);
        harness.fake().reproduce(ProviderBug.KWALLET_READS_A_LOCKED_ITEM_AS_EMPTY);
        harness.fake().lockCollection();
        harness.fake().setRefuseCollectionUnlock(true);
        return collection;
    }

    @Test
    void aRefusedUnlockGivesNoSecret() throws Exception {
        CollectionInterface collection = refusedUnlock();

        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH).map(String::new),
                "no secret, not an empty one");
        assertEquals(0, harness.fake().lockedItemReads(), "the locked item is not read");
    }

    @Test
    void aRefusedUnlockCallsNoCallback() throws Exception {
        CollectionInterface collection = refusedUnlock();

        Optional<Object> result = collection.withSecret(FakeSecretService.ITEM_PATH,
                secret -> fail("called back with a secret of " + secret.length + " chars"));

        assertEquals(Optional.empty(), result);
        assertEquals(0, harness.fake().lockedItemReads(), "the locked item is not read");
    }

    @Test
    void aBulkReadSkipsALockedItem() throws Exception {
        // The item is locked on its own, as KeePassXC locks one, and the user dismisses the
        // dialog that would unlock it.
        CollectionInterface collection = harness.start(true);
        harness.fake().reproduce(ProviderBug.KWALLET_READS_A_LOCKED_ITEM_AS_EMPTY);
        harness.fake().setDismissPrompts(true);

        Optional<Map<String, char[]>> secrets = collection.getSecrets();

        assertTrue(secrets.isPresent(), "the collection is read");
        assertEquals(Set.of(), secrets.get().keySet(), "the locked item is skipped");
        assertEquals(0, harness.fake().lockedItemReads(), "and not read");
    }

    @Test
    void aBulkReadReadsAnUnlockedItem() throws Exception {
        // The counterpart of the test above: the skip there is the lock check's.
        CollectionInterface collection = harness.start(false);
        harness.fake().reproduce(ProviderBug.KWALLET_READS_A_LOCKED_ITEM_AS_EMPTY);

        Optional<Map<String, char[]>> secrets = collection.getSecrets();

        assertTrue(secrets.isPresent(), "the collection is read");
        assertEquals(FakeSecretService.SECRET_VALUE,
                new String(secrets.get().get(FakeSecretService.ITEM_PATH)));
    }
}
