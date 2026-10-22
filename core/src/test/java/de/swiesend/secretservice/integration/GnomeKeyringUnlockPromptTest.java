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
            settle();
            assertEquals(List.of(), fake.dismissCalls(), "the prompt was left open");
            assertFalse(fake.hasAborted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void anInterruptedWaitLeavesTheLaterUnlockPromptsOpenToo() throws Exception {
        // The provider is told on an interrupted thread too, and the answer is kept.
        FakeSecretService fake = gnomeKeyring();
        DBusPath first = unlockPrompt();
        try {
            Thread.currentThread().interrupt();
            assertNull(prompt.await(first, Duration.ofSeconds(5)));
        } finally {
            Thread.interrupted();
        }
        DBusPath second = unlockPrompt();

        assertNull(prompt.await(second, Duration.ofSeconds(1)), "nobody answered");

        settle();
        assertEquals(List.of(), fake.dismissCalls());
        assertFalse(fake.hasAborted());
    }

    /**
     * Gives a {@code Dismiss} that went out the time to reach the fake: on an interrupted thread,
     * the call returns before its reply, and the fake records it on a thread of its own.
     */
    private static void settle() throws InterruptedException {
        Thread.sleep(500);
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

    // ---- one dialog for every request ----------------------------------------------------------

    @Test
    void aSecondReadWaitsOnTheDialogThatTheFirstLeftOpen() throws Exception {
        CollectionInterface collection = lockedGnomeKeyring();
        FakeSecretService fake = harness.fake();
        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH), "nobody answered in time");

        harness.service().setTimeout(Duration.ofSeconds(10));
        Thread user = answerWhenShown(fake, true);
        char[] secret = collection.getSecret(FakeSecretService.ITEM_PATH).orElseThrow();
        user.join(5_000);

        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), secret, "the answer came now");
        assertEquals(1, fake.unlockRequests().size(), "gnome-keyring was asked once");
        assertEquals(1, fake.promptCalls().size(), "and showed one dialog");
    }

    @Test
    void aCancelOfThatDialogRefusesTheReadThatWaitsOnIt() throws Exception {
        CollectionInterface collection = lockedGnomeKeyring();
        FakeSecretService fake = harness.fake();
        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH), "nobody answered in time");

        harness.service().setTimeout(Duration.ofSeconds(10));
        Thread user = answerWhenShown(fake, false);
        long start = java.lang.System.nanoTime();
        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH));
        long waited = (java.lang.System.nanoTime() - start) / 1_000_000;
        user.join(5_000);

        assertTrue(waited < 5_000, "the cancel refused it, after " + waited + " ms, not its timeout");
        assertFalse(fake.hasPendingPrompt(), "and brought up no other dialog");
        assertEquals(1, fake.unlockRequests().size());
        assertTrue(fake.isCollectionLocked());
    }

    @Test
    void anAnswerWhileNobodyWaitsLeavesNothingToAsk() throws Exception {
        CollectionInterface collection = lockedGnomeKeyring();
        FakeSecretService fake = harness.fake();
        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH), "nobody answered in time");

        fake.approvePendingPrompt();

        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(),
                collection.getSecret(FakeSecretService.ITEM_PATH).orElseThrow());
        assertEquals(1, fake.unlockRequests().size(), "the collection was unlocked");
    }

    @Test
    void aCancelWhileNobodyWaitsLetsTheNextReadAskAgain() throws Exception {
        CollectionInterface collection = lockedGnomeKeyring();
        FakeSecretService fake = harness.fake();
        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH), "nobody answered in time");
        fake.refusePendingPrompt();
        awaitPromptCompleted(fake);

        harness.service().setTimeout(Duration.ofSeconds(10));
        Thread user = answerWhenShown(fake, true);
        char[] secret = collection.getSecret(FakeSecretService.ITEM_PATH).orElseThrow();
        user.join(5_000);

        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), secret);
        assertEquals(2, fake.unlockRequests().size(), "a new request, after the user refused the old one");
    }

    @Test
    void readsThroughAnotherCollectionObjectOfTheConnectionWaitOnTheSameDialog() throws Exception {
        // As SimpleCollection's instances share their connection, and an application may open one
        // for each call.
        CollectionInterface collection = lockedGnomeKeyring();
        FakeSecretService fake = harness.fake();
        assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH), "nobody answered in time");

        harness.service().setTimeout(Duration.ofSeconds(10));
        try (CollectionInterface another = harness.service().openSession().orElseThrow()
                .collection(FakeSecretService.COLLECTION_LABEL, Optional.empty()).orElseThrow()) {
            Thread user = answerWhenShown(fake, true);
            char[] secret = another.getSecret(FakeSecretService.ITEM_PATH).orElseThrow();
            user.join(5_000);

            assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), secret);
        }
        assertEquals(1, fake.unlockRequests().size(), "gnome-keyring was asked once");
    }

    @Test
    void readsThatComeTogetherShareOneDialog() throws Exception {
        CollectionInterface collection = lockedGnomeKeyring();
        FakeSecretService fake = harness.fake();
        harness.service().setTimeout(Duration.ofSeconds(10));
        java.util.concurrent.ExecutorService readers = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            Thread user = answerWhenShown(fake, true);
            java.util.concurrent.Future<Optional<char[]>> first =
                    readers.submit(() -> collection.getSecret(FakeSecretService.ITEM_PATH));
            java.util.concurrent.Future<Optional<char[]>> second =
                    readers.submit(() -> collection.getSecret(FakeSecretService.ITEM_PATH));

            assertTrue(first.get(15, java.util.concurrent.TimeUnit.SECONDS).isPresent());
            assertTrue(second.get(15, java.util.concurrent.TimeUnit.SECONDS).isPresent());
            user.join(5_000);
        } finally {
            readers.shutdownNow();
        }
        assertEquals(1, fake.unlockRequests().size(), "gnome-keyring was asked once");
    }

    @Test
    void aReadWhosePromptGnomeKeyringStrandsEndsOnceTheCollectionIsUnlocked() throws Exception {
        // gnome-keyring 51.1: another application dismisses the prompt of the dialog on the screen,
        // and the dialog stays. The user's answer to it unlocks the collection, and the prompt that
        // waits behind it, the read's, never completes.
        CollectionInterface collection = harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK,
                ProviderBug.GNOME_KEYRING_STRANDS_THE_UNLOCKS_BEHIND_A_DISMISSED_DIALOG);
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        harness.service().setTimeout(Duration.ofSeconds(10));
        prompt = new Prompt(harness.service().getService());
        DBusPath others = unlockPrompt();
        assertTrue(prompt.prompt(others), "another application's dialog is on the screen");

        java.util.concurrent.ExecutorService reader = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            java.util.concurrent.Future<Optional<char[]>> read =
                    reader.submit(() -> collection.getSecret(FakeSecretService.ITEM_PATH));
            awaitPromptCalls(fake, 2);
            assertTrue(prompt.dismiss(others), "the other application gives up");
            fake.approvePendingPrompt();

            long start = java.lang.System.nanoTime();
            Optional<char[]> secret = read.get(15, java.util.concurrent.TimeUnit.SECONDS);
            long waited = (java.lang.System.nanoTime() - start) / 1_000_000;
            assertTrue(secret.isPresent(), "the collection is unlocked");
            assertTrue(waited < 5_000, "the read ended after " + waited + " ms, not with its timeout");
        } finally {
            reader.shutdownNow();
        }
        assertFalse(fake.hasAborted());

        fake.lockCollection();
        Thread user = answerWhenShown(fake, true);
        assertTrue(collection.getSecret(FakeSecretService.ITEM_PATH).isPresent(),
                "the next read asks anew, instead of waiting on the stranded prompt");
        user.join(5_000);
    }

    @Test
    void aServiceKeepsOnlyTheUnlockPromptsOfItsRecentUnlocks() throws Exception {
        // A Service that lives as long as the application, as SimpleCollection's does.
        gnomeKeyring();
        de.swiesend.secretservice.Service service = harness.service().getService();
        for (int i = 0; i < 300; i++) unlockPrompt();

        java.lang.reflect.Field field = de.swiesend.secretservice.Service.class.getDeclaredField("unlockPrompts");
        field.setAccessible(true);
        int kept = ((java.util.Set<?>) field.get(service)).size();
        assertTrue(kept > 0 && kept <= 128, kept + " unlock prompts kept");
    }

    /** Waits until the fake has seen {@code count} calls of Prompt. */
    private static void awaitPromptCalls(FakeSecretService fake, int count) throws InterruptedException {
        long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
        while (fake.promptCalls().size() < count && java.lang.System.nanoTime() < deadline) Thread.sleep(20);
        assertEquals(count, fake.promptCalls().size(), "the prompts shown");
    }

    /** The fake as gnome-keyring, its collection locked and unlocking through its dialog, a 1 s timeout. */
    private CollectionInterface lockedGnomeKeyring() throws Exception {
        CollectionInterface collection = harness.startAsGnomeKeyring(false);
        harness.fake().reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_UNLOCK_DIALOG,
                ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK);
        harness.fake().lockCollection();
        harness.fake().setRequirePromptForCollectionUnlock(true);
        harness.service().setTimeout(Duration.ofSeconds(1));
        return collection;
    }

    /**
     * Answers the dialog from another thread once it is on the screen, as the user does, a moment
     * later: the requests that wait on it have joined by then.
     */
    private static Thread answerWhenShown(FakeSecretService fake, boolean approve) {
        Thread user = new Thread(() -> {
            try {
                long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
                while (!fake.hasPendingPrompt() && java.lang.System.nanoTime() < deadline) Thread.sleep(20);
                Thread.sleep(300);
                if (approve) fake.approvePendingPrompt();
                else fake.refusePendingPrompt();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "user");
        user.setDaemon(true);
        user.start();
        return user;
    }

    /** Waits until the fake has no prompt waiting for the user. */
    private static void awaitPromptCompleted(FakeSecretService fake) throws InterruptedException {
        long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
        while (fake.hasPendingPrompt() && java.lang.System.nanoTime() < deadline) Thread.sleep(20);
        // The Completed signal reaches the library a moment after the fake sent it.
        Thread.sleep(200);
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
