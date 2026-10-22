package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A prompt's wait took its timeout only once the prompt was on the screen: a null one threw there,
 * and a huge one overflowed {@link Duration#toNanos()}, with the prompt left open and nobody to
 * collect its answer.
 *
 * <p>Against {@link FakeSecretService} as gnome-keyring, whose unlock dialog the test answers.</p>
 */
class PromptTimeoutTest {

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
    void aNullTimeoutIsRefusedBeforeThePromptIsShown() throws Exception {
        FakeSecretService fake = lockedGnomeKeyring();
        prompt = new Prompt(harness.service().getService());
        DBusPath unlock = harness.service().getService().unlock(List.of(COLLECTION)).orElseThrow().b;

        assertThrows(NullPointerException.class, () -> prompt.await(unlock, null));
        assertEquals(List.of(), fake.promptCalls(), "no dialog was shown");
    }

    @Test
    void theServiceTakesNoNullTimeout() throws Exception {
        harness.start(false);

        assertThrows(NullPointerException.class, () -> harness.service().setTimeout(null));
    }

    @Test
    void aHugeTimeoutOfAPromptWaitsForTheAnswer() throws Exception {
        FakeSecretService fake = lockedGnomeKeyring();
        prompt = new Prompt(harness.service().getService());
        DBusPath unlock = harness.service().getService().unlock(List.of(COLLECTION)).orElseThrow().b;
        Thread user = answerWhenShown(fake);

        de.swiesend.secretservice.interfaces.Prompt.Completed completed =
                prompt.await(unlock, Duration.ofSeconds(Long.MAX_VALUE));
        user.join(5_000);

        assertNotNull(completed, "the user answered");
        assertFalse(completed.dismissed);
    }

    @Test
    void aHugeTimeoutOfTheServiceWaitsForTheAnswer() throws Exception {
        CollectionInterface collection = harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        harness.service().setTimeout(Duration.ofSeconds(Long.MAX_VALUE));
        Thread user = answerWhenShown(fake);

        assertTrue(collection.getSecret(FakeSecretService.ITEM_PATH).isPresent(), "the answer unlocked it");
        user.join(5_000);
    }

    private FakeSecretService lockedGnomeKeyring() throws Exception {
        harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        return fake;
    }

    /** Answers the dialog from another thread once it is on the screen, as the user does. */
    private static Thread answerWhenShown(FakeSecretService fake) {
        Thread user = new Thread(() -> {
            try {
                long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
                while (!fake.hasPendingPrompt() && java.lang.System.nanoTime() < deadline) Thread.sleep(20);
                Thread.sleep(200);
                fake.approvePendingPrompt();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "user");
        user.setDaemon(true);
        user.start();
        return user;
    }
}
