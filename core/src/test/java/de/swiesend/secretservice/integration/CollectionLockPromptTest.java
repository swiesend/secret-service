package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KeePassXC answers {@code Lock} with a prompt and locks only once the prompt is called;
 * gnome-keyring locks at once. The library never called that prompt, so {@code lock()} never locked
 * such a collection, and {@code unlockWithUserPermission()}, which locks first, failed there, and
 * every read of all secrets with it.
 *
 * <p>Against {@link FakeSecretService}, which puts the collection's lock behind a prompt when told
 * to, as KeePassXC does.</p>
 */
class CollectionLockPromptTest {

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

    @Test
    void lockCarriesOutTheProvidersPrompt() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionLock(true);
        Thread approver = approveWhenPrompted(fake);

        assertTrue(collection.lock(), "the lock completes through the provider's prompt");
        assertTrue(fake.isCollectionLocked(), "and the collection really is locked");
        approver.join(5_000);
    }

    @Test
    void aLockedCollectionIsNotLockedAgain() throws Exception {
        // KWallet answers Lock of a closed wallet with an error.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.KWALLET_REFUSES_TO_LOCK_A_LOCKED_WALLET);
        fake.lockCollection();

        assertTrue(collection.lock(), "the collection is locked");
        assertEquals(List.of(), fake.lockCalls(), "and nothing was asked of the provider");
    }

    @Test
    void lockDismissesThePromptWhenPromptingIsDisabled() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionLock(true);
        assertTrue(collection.disablePrompt());

        assertFalse(collection.lock(), "the lock needs a prompt, and prompting is disabled");
        assertFalse(fake.isCollectionLocked(), "so the collection stays unlocked");
    }

    @Test
    void readingAllSecretsWorksWhereLockingNeedsAPrompt() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionLock(true);

        Optional<Map<String, char[]>> secrets = collection.getSecrets();

        assertTrue(secrets.isPresent(), "such a provider confirms access itself, so the read goes ahead");
        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(),
                secrets.get().get(FakeSecretService.ITEM_PATH));
        assertFalse(fake.isCollectionLocked(), "and the user's collection was not locked for it");
    }

    @Test
    void readingAllSecretsLocksAndUnlocksWhereLockingNeedsNoPrompt() throws Exception {
        // gnome-keyring's case, and the protection against CVE-2018-19358: before all secrets are
        // read, the collection is locked, then unlocked through the provider.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();

        Optional<Map<String, char[]>> secrets = collection.getSecrets();

        assertTrue(secrets.isPresent(), "the provider unlocked the collection again");
        assertEquals(List.of(FakeSecretService.COLLECTION_PATH), fake.unlockCalls(),
                "the collection was locked first, then unlocked through the provider");
    }

    /**
     * Answers the provider's prompt from another thread, as the user would, while the caller waits
     * for it. Polls rather than sleeping a fixed time: the client makes several D-Bus round trips
     * before the fake has a prompt outstanding.
     */
    private static Thread approveWhenPrompted(FakeSecretService fake) {
        Thread approver = new Thread(() -> {
            try {
                long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
                while (!fake.hasPendingPrompt() && java.lang.System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                // Only a prompt that exists: a Completed signal sent for none could be taken as a
                // stale answer by a later wait on the same bus.
                if (fake.hasPendingPrompt()) {
                    fake.approvePendingPrompt();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "approver");
        approver.setDaemon(true);
        approver.start();
        return approver;
    }
}
