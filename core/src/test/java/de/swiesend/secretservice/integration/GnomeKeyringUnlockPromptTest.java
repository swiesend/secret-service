package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * gnome-keyring aborts when a client dismisses an unlock prompt while an unlock dialog is on the
 * screen: before 51 for the dialog's own prompt, up to 51.1 for one that waits behind it or was
 * never shown. The library left no such prompt open: it dismissed one that nobody answered within
 * its timeout, and with prompting disabled it dismissed one unshown. Every application then lost
 * its session, and the login keyring came back locked.
 *
 * <p>Against {@link FakeSecretService} as gnome-keyring, with those bugs reproduced.</p>
 */
class GnomeKeyringUnlockPromptTest {

    private static final DBusPath COLLECTION = new DBusPath(FakeSecretService.COLLECTION_PATH);

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private Prompt prompt;

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        if (prompt != null) prompt.getSignalHandler().disconnect();
        harness.stop();
    }

    @Test
    void anUnlockPromptThatNobodyAnswersIsLeftOpen() throws Exception {
        FakeSecretService fake = gnomeKeyring();
        DBusPath unlock = unlockPrompt();

        assertNull(prompt.await(unlock, Duration.ofSeconds(1)), "nobody answered the dialog");

        assertEquals(List.of(), fake.dismissCalls(), "the prompt was left open");
        assertFalse(fake.hasAborted());
        assertTrue(fake.hasPendingPrompt(), "its dialog is still on the screen");
        fake.approvePendingPrompt();
        assertFalse(fake.isCollectionLocked(), "and its answer unlocks the collection");
    }

    @Test
    void anUnlockPromptWhoseWaitIsInterruptedIsLeftOpen() throws Exception {
        FakeSecretService fake = gnomeKeyring();
        DBusPath unlock = unlockPrompt();
        try {
            Thread.currentThread().interrupt();
            assertNull(prompt.await(unlock, Duration.ofSeconds(5)));

            assertTrue(Thread.interrupted(), "the interrupt is kept for the caller");
            assertEquals(List.of(), fake.dismissCalls(), "the prompt was left open");
            assertFalse(fake.hasAborted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void anUnlockPromptThatWaitsBehindAnotherDialogIsLeftOpen() throws Exception {
        FakeSecretService fake = gnomeKeyring();
        DBusPath other = unlockPrompt();
        assertTrue(prompt.prompt(other), "another application's dialog is on the screen");
        DBusPath waiting = unlockPrompt();

        assertNull(prompt.await(waiting, Duration.ofSeconds(1)), "nobody answered");

        assertEquals(List.of(), fake.dismissCalls());
        assertFalse(fake.hasAborted());
    }

    @Test
    void anyOtherPromptThatNobodyAnswersIsDismissedOnGnomeKeyringToo() throws Exception {
        harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        Service service = harness.service().getService();
        prompt = new Prompt(service);
        fake.setRequirePromptForCollectionLock(true);
        DBusPath lock = service.lock(List.of(COLLECTION)).orElseThrow().b;

        assertNull(prompt.await(lock, Duration.ofSeconds(1)), "nobody answered the lock prompt");

        assertEquals(List.of(lock.getPath()), fake.dismissCalls(), "which is not an unlock prompt");
    }

    @Test
    void elsewhereAnUnlockPromptThatNobodyAnswersIsDismissed() throws Exception {
        harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        Service service = harness.service().getService();
        prompt = new Prompt(service);
        DBusPath unlock = service.unlock(List.of(COLLECTION)).orElseThrow().b;

        assertNull(prompt.await(unlock, Duration.ofSeconds(1)));

        assertEquals(List.of(unlock.getPath()), fake.dismissCalls(), "the provider is not gnome-keyring");
    }

    @Test
    void aReadWhoseDialogNobodyAnswersFailsAndLeavesGnomeKeyringRunning() throws Exception {
        CollectionInterface collection = harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_UNLOCK_DIALOG);
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        harness.service().setTimeout(Duration.ofSeconds(1));

        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH),
                "nobody answered the unlock dialog in time");

        assertFalse(fake.hasAborted(), "gnome-keyring still runs");
        assertTrue(fake.hasPendingPrompt(), "with its dialog on the screen");
        fake.approvePendingPrompt();
        char[] secret = collection.getSecret(FakeSecretService.ITEM_PATH).orElseThrow();
        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), secret,
                "the user answered later, and the collection is unlocked");
    }

    @Test
    void withPromptingDisabledGnomeKeyringIsNotAskedToUnlock() throws Exception {
        CollectionInterface collection = harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        assertTrue(collection.disablePrompt());

        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH));

        assertEquals(List.of(), fake.unlockCalls(), "no Unlock, whose prompt would have to be dismissed unshown");
        assertEquals(List.of(), fake.dismissCalls());
    }

    /** The fake as gnome-keyring, with the bugs reproduced, and the collection locked. */
    private FakeSecretService gnomeKeyring() throws Exception {
        harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_UNLOCK_DIALOG,
                ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK);
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        prompt = new Prompt(harness.service().getService());
        return fake;
    }

    private DBusPath unlockPrompt() {
        return harness.service().getService().unlock(List.of(COLLECTION)).orElseThrow().b;
    }
}
