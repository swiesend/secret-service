package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code unlockWithUserPermission()} locks the collection and unlocks it through the provider's
 * dialog. With prompting disabled there is no dialog, and on gnome-keyring the collection then
 * stayed locked: for every application on the desktop, and for the login keyring all of them
 * started to prompt.
 *
 * <p>Against {@link FakeSecretService}, which locks at once and unlocks only through a prompt when
 * told to, as gnome-keyring does.</p>
 */
class UserPermissionTest {

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
    void readingAllSecretsAsksThroughTheUnlockDialog() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionUnlock(true);
        Thread approver = approveWhenPrompted(fake);

        Optional<Map<String, char[]>> secrets = collection.getSecrets();

        assertTrue(secrets.isPresent(), "the user confirmed access in the unlock dialog");
        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(),
                secrets.get().get(FakeSecretService.ITEM_PATH));
        assertFalse(fake.isCollectionLocked());
        approver.join(5_000);
    }

    @Test
    void withPromptingDisabledTheCollectionIsNotLocked() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionUnlock(true);
        assertTrue(collection.disablePrompt());

        assertTrue(collection.getSecrets().isEmpty(),
                "without the dialog the user cannot confirm access, so the read is refused");
        assertFalse(fake.isCollectionLocked(),
                "and the collection was not locked, which nothing could have undone");
    }

    @Test
    void aCollectionWithAStoredPasswordIsLockedForTheFirstBulkReadOnly() throws Exception {
        // The stored password unlocks it again, and counts as the permission once, as the
        // dialog's answer does.
        harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        try (CollectionInterface collection = harness.service().openSession().orElseThrow()
                .collection(FakeSecretService.COLLECTION_LABEL, Optional.of("password")).orElseThrow()) {

            assertTrue(collection.getSecrets().isPresent());
            assertTrue(collection.getSecrets().isPresent());

            assertEquals(1, fake.lockCalls().size(), "locked once, not for every read");
            assertEquals(1, fake.masterPasswordUnlocks());
        }
    }

    @Test
    void aStoredPasswordThatDoesNotUnlockTheCollectionAgainAsksThroughTheDialog() throws Exception {
        // A stale password, after the user changed the collection's: the call locked the collection,
        // and does not leave it locked for every application.
        harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.setRefuseMasterPassword(true);
        fake.setRequirePromptForCollectionUnlock(true);
        try (CollectionInterface collection = harness.service().openSession().orElseThrow()
                .collection(FakeSecretService.COLLECTION_LABEL, Optional.of("stale")).orElseThrow()) {
            Thread user = approveWhenPrompted(fake);

            assertTrue(collection.getSecrets().isPresent(), "the user unlocked it through the dialog");
            user.join(5_000);
            assertFalse(fake.isCollectionLocked());
        }
    }

    @Test
    void aLockWhoseReplyComesTooLateCountsAsTheProviderTellsIt() throws Exception {
        // A busy provider locks, and its reply comes after the library's two-second reply timeout.
        CollectionInterface collection = harness.start(false);
        harness.fake().setLockReplyDelay(Duration.ofSeconds(3));

        assertTrue(collection.lock(), "the collection is locked");
    }

    @Test
    void aPermissionWhoseLockReplyComesTooLateUnlocksTheCollectionAgain() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setLockReplyDelay(Duration.ofSeconds(3));

        assertTrue(collection.unlockWithUserPermission());
        assertFalse(fake.isCollectionLocked(), "it is not left locked for every application");
    }

    /** Answers the provider's prompt from another thread, as the user would. */
    private static Thread approveWhenPrompted(FakeSecretService fake) {
        Thread approver = new Thread(() -> {
            try {
                long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
                while (!fake.hasPendingPrompt() && java.lang.System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
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
