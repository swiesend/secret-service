package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.handlers.SignalHandler;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.interfaces.DBus;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Whose signals count. Any client on the session bus can send a signal for any path, and a signal's
 * match rule names no sender: a {@code Completed} from another client answered a prompt, with the
 * user's consent or with a refusal. Only the owner of the provider's bus name answers one.
 *
 * <p>Against {@link FakeSecretService}; the other client has a connection of its own to the bus.</p>
 */
class SignalSenderTest {

    private static final DBusPath COLLECTION = new DBusPath(FakeSecretService.COLLECTION_PATH);

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private Prompt prompt;
    private SignalHandler handler;

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        if (prompt != null) prompt.getSignalHandler().disconnect();
        if (handler != null) handler.disconnect();
        harness.stop();
    }

    @Test
    void aConsentFromAnotherClientIsNotThePromptsAnswer() throws Exception {
        FakeSecretService fake = lockedBehindAPrompt();
        DBusPath unlock = unlockPrompt();
        Thread other = sendWhenShown(fake, harness.connectAnother(), false);

        Prompt.Completed completed = prompt.await(unlock, Duration.ofSeconds(2));
        other.join(5_000);

        assertNull(completed, "nobody answered the dialog: the consent came from another client");
        assertTrue(fake.isCollectionLocked());
    }

    @Test
    void aRefusalFromAnotherClientDoesNotEndTheWait() throws Exception {
        FakeSecretService fake = lockedBehindAPrompt();
        DBusPath unlock = unlockPrompt();
        Thread other = sendWhenShown(fake, harness.connectAnother(), true);
        Thread user = answerAfter(fake, 600);

        Prompt.Completed completed = prompt.await(unlock, Duration.ofSeconds(5));
        other.join(5_000);
        user.join(5_000);

        assertNotNull(completed, "the user answered the dialog");
        assertFalse(completed.dismissed, "with a consent, which the other client's refusal did not replace");
        assertFalse(fake.isCollectionLocked());
    }

    @Test
    void aRefusalFromAnotherClientDoesNotRefuseAReadThatWaitsOnGnomeKeyringsDialog() throws Exception {
        CollectionInterface collection = harness.startAsGnomeKeyring(false);
        FakeSecretService fake = harness.fake();
        fake.reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_UNLOCK_DIALOG,
                ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK);
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        harness.service().setTimeout(Duration.ofSeconds(10));
        Thread other = sendWhenShown(fake, harness.connectAnother(), true);
        Thread user = answerAfter(fake, 600);

        Optional<char[]> secret = collection.getSecret(FakeSecretService.ITEM_PATH);
        other.join(5_000);
        user.join(5_000);

        assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), secret.orElseThrow(),
                "the user unlocked the collection; the other client's refusal was not the dialog's answer");
        assertEquals(1, fake.unlockRequests().size(), "and gnome-keyring was asked once");
    }

    @Test
    void aSignalFromAnotherClientIsNotReceived() throws Exception {
        harness.start(false);
        prompt = new Prompt(harness.service().getService());
        DBusConnection other = harness.connectAnother();

        other.sendMessage(completed(FakeSecretService.PROMPT_PATH, false));
        Thread.sleep(500);
        assertEquals(0, prompt.getSignalHandler().getCount(), "another client's signal is no signal of the provider");
        assertNull(prompt.getSignalHandler().getLastHandledSignal(Prompt.Completed.class));

        // The fake provider and the library share one connection in this fixture.
        harness.clientConnection().sendMessage(completed(FakeSecretService.PROMPT_PATH, true));
        assertTrue(PromptResultTest.received(prompt, 1), "the provider's own signal is received");
    }

    @Test
    void theSignalsOfTheNameSOwnerAreReceivedAndFollowItToItsNextOwner() throws Exception {
        // A provider that starts again has another unique name.
        final String name = "org.example.Provider";
        harness.start(false);
        DBusConnection first = harness.connectAnother();
        DBusConnection second = harness.connectAnother();
        handler = new SignalHandler();
        handler.connect(harness.clientConnection(), List.of(Prompt.Completed.class), "/", name);

        first.sendMessage(completed(FakeSecretService.PROMPT_PATH, false));
        Thread.sleep(300);
        assertEquals(0, handler.getCount(), "nobody owns the name: no signal is the provider's");

        first.requestBusName(name);
        first.sendMessage(completed(FakeSecretService.PROMPT_PATH, false));
        assertTrue(received(handler, 1), "the owner's signal");

        first.releaseBusName(name);
        second.requestBusName(name);
        second.sendMessage(completed(FakeSecretService.PROMPT_PATH, false));
        assertTrue(received(handler, 2), "the next owner's signal");

        first.sendMessage(completed(FakeSecretService.PROMPT_PATH, false));
        Thread.sleep(300);
        assertEquals(2, handler.getCount(), "and none of the client that owned the name before");
    }

    @Test
    void anotherClientCannotAnnounceItselfAsTheProvider() throws Exception {
        // The handler follows the owner of the provider's name through the bus's NameOwnerChanged,
        // a signal like any other: a client can send one by that name, but not as the bus.
        harness.start(false);
        prompt = new Prompt(harness.service().getService());
        DBusConnection other = harness.connectAnother();

        other.sendMessage(new DBus.NameOwnerChanged("/org/freedesktop/DBus", "org.freedesktop.secrets",
                harness.clientConnection().getUniqueName(), other.getUniqueName()));
        other.sendMessage(completed(FakeSecretService.PROMPT_PATH, false));
        Thread.sleep(500);
        assertEquals(0, prompt.getSignalHandler().getCount(), "it is not taken for the provider");

        harness.clientConnection().sendMessage(completed(FakeSecretService.PROMPT_PATH, true));
        assertTrue(PromptResultTest.received(prompt, 1), "and the provider still is");
    }

    @Test
    void aHandlerWithoutAProviderReceivesEverySendersSignals() throws Exception {
        harness.start(false);
        handler = new SignalHandler();
        handler.connect(harness.clientConnection(), List.of(Prompt.Completed.class), "/");

        harness.connectAnother().sendMessage(completed(FakeSecretService.PROMPT_PATH, false));

        assertTrue(received(handler, 1), "as before, for a caller that connects a handler itself");
    }

    /** The fake with its collection locked, which it unlocks through a prompt that a test answers. */
    private FakeSecretService lockedBehindAPrompt() throws Exception {
        harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        prompt = new Prompt(harness.service().getService());
        return fake;
    }

    private DBusPath unlockPrompt() {
        Service service = harness.service().getService();
        return service.unlock(List.of(COLLECTION)).orElseThrow().b;
    }

    private static Prompt.Completed completed(String path, boolean dismissed) throws Exception {
        return new Prompt.Completed(path, dismissed, new Variant<>(new ArrayList<DBusPath>(), "ao"));
    }

    /**
     * Sends a {@code Completed} for the prompt that the fake shows next, from {@code other}, once it
     * is shown: the wait for its answer has begun by then.
     */
    private static Thread sendWhenShown(FakeSecretService fake, DBusConnection other, boolean dismissed) {
        Thread sender = new Thread(() -> {
            try {
                long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
                while (fake.promptCalls().isEmpty() && java.lang.System.nanoTime() < deadline) Thread.sleep(20);
                Thread.sleep(100);
                other.sendMessage(completed(fake.promptCalls().get(0), dismissed));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }, "other-client");
        sender.setDaemon(true);
        sender.start();
        return sender;
    }

    /** Approves the fake's dialog, as the user does, {@code millis} after it is shown. */
    private static Thread answerAfter(FakeSecretService fake, long millis) {
        Thread user = new Thread(() -> {
            try {
                long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
                while (fake.promptCalls().isEmpty() && java.lang.System.nanoTime() < deadline) Thread.sleep(20);
                Thread.sleep(millis);
                fake.approvePendingPrompt();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "user");
        user.setDaemon(true);
        user.start();
        return user;
    }

    /** Waits up to five seconds for {@code handler} to have received {@code count} signals. */
    private static boolean received(SignalHandler handler, int count) throws InterruptedException {
        long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
        while (handler.getCount() < count && java.lang.System.nanoTime() < deadline) Thread.sleep(20);
        return handler.getCount() >= count;
    }
}
