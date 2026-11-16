package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
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
 * started to prompt. So the user is not asked then, and access is the provider's to enforce.
 *
 * <p>Where the user is asked, the answer binds the bulk reads and the deletions alike: a deletion
 * went ahead on a permission that was refused. Where the provider does not lock the collection,
 * there is no dialog to ask in: the bulk reads are refused, and a deletion goes ahead.</p>
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
    void withPromptingDisabledTheUserIsNotAskedAndTheCollectionIsNotLocked() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionUnlock(true);
        assertTrue(collection.disablePrompt());

        assertTrue(collection.unlockWithUserPermission(), "the provider has the collection unlocked");
        assertEquals(List.of(), fake.lockCalls(),
                "and the collection was not locked, which nothing could have undone");
        assertEquals(List.of(), fake.promptCalls(), "nor was a dialog asked for");
    }

    @Test
    void withPromptingDisabledAccessIsTheProvidersToEnforce() throws Exception {
        // The bulk read and the deletion alike: neither is refused in the user's place.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionUnlock(true);
        assertTrue(collection.disablePrompt());

        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(),
                collection.getSecrets().orElseThrow().get(FakeSecretService.ITEM_PATH),
                "the provider gives the secrets of its unlocked collection");
        assertTrue(collection.deleteItems(List.of(FakeSecretService.ITEM_PATH)), "and deletes its item");
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
        assertEquals(List.of(), fake.lockCalls());
    }

    @Test
    void withPromptingDisabledALockedCollectionStaysLockedAndRefusesBoth() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionUnlock(true);
        fake.lockCollection();
        assertTrue(collection.disablePrompt());

        assertFalse(collection.unlockWithUserPermission());
        assertEquals(Optional.empty(), collection.getSecrets().map(Map::keySet));
        assertFalse(collection.deleteItem(FakeSecretService.ITEM_PATH));
        assertFalse(collection.deleteItems(List.of(FakeSecretService.ITEM_PATH)));
        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH), "the item is kept");
        assertTrue(fake.isCollectionLocked());
    }

    @Test
    void aDeletionThatTheUserRefusesDeletesNothing() throws Exception {
        // The user cancels the unlock dialog.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setRequirePromptForCollectionUnlock(true);
        fake.setDismissPrompts(true);

        assertFalse(collection.deleteItems(List.of(FakeSecretService.ITEM_PATH, FakeSecretService.ITEM_PATH)));

        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH), "the item is kept");
        assertEquals(1, fake.promptCalls().size(), "asked once for the list, and not again after the refusal");
    }

    @Test
    void aCollectionThatTheProviderDoesNotLockRefusesTheBulkReadsAndDeletesItsItems() throws Exception {
        // The user cannot be asked through the unlock dialog. No secret is handed out on that, and
        // the items can still be deleted: there is no other way to delete them.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setCollectionCannotBeLocked(true);

        assertFalse(collection.unlockWithUserPermission(), "the user could not be asked");
        assertEquals(Optional.empty(), collection.getSecrets().map(Map::keySet),
                "no secret is read without the permission");
        assertTrue(collection.deleteItem(FakeSecretService.ITEM_PATH), "a deletion goes ahead");
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
        assertFalse(fake.isCollectionLocked());
    }

    @Test
    void aCollectionThatIsNamedAsLockedAndStaysUnlockedDeletesItsItemsToo() throws Exception {
        // gnome-keyring's session collection: Lock answers with its path and no prompt.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setLockNamesTheCollectionWithoutLocking(true);

        assertEquals(Optional.empty(), collection.getSecrets().map(Map::keySet));
        assertTrue(collection.deleteItems(List.of(FakeSecretService.ITEM_PATH)));
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
    }

    @Test
    void aLockCallWithoutAnAnswerIsNoCollectionThatCannotBeLocked() throws Exception {
        // The provider may lock yet: nothing says that it does not lock this collection. The
        // deletion is refused as the bulk read is.
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.setCollectionCannotBeLocked(true);
        fake.setLockReplyDelay(Duration.ofSeconds(3));

        String log = logOf(() -> assertFalse(collection.deleteItem(FakeSecretService.ITEM_PATH)));

        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH), "the item is kept");
        assertTrue(log.contains("Without the user's permission the item is not deleted."), log);
        assertFalse(log.lines().anyMatch(line -> line.contains(" INFO ") && line.contains(FakeSecretService.ITEM_PATH)),
                "and the refusal is logged without the path, which is the caller's text");
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
    void aCollectionWithAStoredPasswordThatIsTheDefaultIsUnlockedWithIt() throws Exception {
        // The user made it the default since: the alias points to it, and its id is its own.
        harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.setDefaultAlias(FakeSecretService.COLLECTION_PATH);
        fake.setRequirePromptForCollectionUnlock(true);
        harness.service().setTimeout(Duration.ofSeconds(1));
        try (CollectionInterface collection = harness.service().openSession().orElseThrow()
                .collection(FakeSecretService.COLLECTION_LABEL, Optional.of("password")).orElseThrow()) {
            fake.lockCollection();

            assertTrue(collection.getSecret(FakeSecretService.ITEM_PATH).isPresent());
            assertEquals(1, fake.masterPasswordUnlocks(), "with the stored password");
            assertEquals(java.util.List.of(), fake.promptCalls(), "not through the dialog");
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

    private static String logOf(Runnable calls) {
        PrintStream original = java.lang.System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        java.lang.System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            calls.run();
        } finally {
            java.lang.System.setErr(original);
        }
        return captured.toString(StandardCharsets.UTF_8);
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
