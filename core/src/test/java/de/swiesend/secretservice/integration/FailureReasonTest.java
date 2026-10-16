package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Failure;
import de.swiesend.secretservice.Failure.Reason;
import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Item;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.handlers.MessageHandler;
import de.swiesend.secretservice.handlers.MessageHandler.Reply;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * The reason that a failed call stands for, as the bus, dbus-java and the provider report it: on a
 * real bus, against {@link FakeSecretService}.
 */
class FailureReasonTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        if (harness.fake() != null) harness.fake().setStallItemProperties(false);
        harness.stop();
    }

    private static Reply readLabel(MessageHandler handler, String itemPath) {
        return handler.getPropertyChecked(Static.Service.SECRETS, itemPath, Static.Interfaces.ITEM, "Label");
    }

    private static Failure failureOf(Reply reply) {
        return Failure.from(reply, "test");
    }

    @Test
    void aReplyThatComesTooLateTimedOut() throws Exception {
        harness.start(false);
        harness.fake().setStallItemProperties(true);

        Failure failure = failureOf(readLabel(harness.rawService().getMessageHandler(), FakeSecretService.ITEM_PATH));

        assertEquals(Reason.TIMED_OUT, failure.reason());
        assertInstanceOf(TimeoutException.class, failure.cause());
    }

    @Test
    void anItemThatDoesNotExistIsNotFound() throws Exception {
        harness.start(false);
        String missing = FakeSecretService.COLLECTION_PATH + "/999";

        // Nothing exports the path, and dbus-java, on which the fake runs, answers with an error
        // named after its own exception class: org.freedesktop.dbus.errors.UnknownObject.
        Failure failure = failureOf(readLabel(harness.rawService().getMessageHandler(), missing));

        assertEquals(Reason.NOT_FOUND, failure.reason(), "error " + failure.errorName());
        assertEquals(Optional.of(false), new Item(Static.Convert.toObjectPath(missing), harness.rawService()).exists());
    }

    @Test
    void aCollectionThatDoesNotExistIsNotFound() throws Exception {
        harness.start(false);

        // The fake names it with NoSuchObject, as a provider does.
        Reply reply = harness.rawService().getMessageHandler().sendChecked(Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS, Static.Interfaces.SERVICE, "ChangeLock", "o",
                new DBusPath(Static.ObjectPaths.collection("missing")));

        assertEquals(Reason.NOT_FOUND, failureOf(reply).reason(), "error " + reply.errorName());
    }

    @Test
    void aProviderThatLeftTheBusIsNoProvider() throws Exception {
        harness.start(false);
        harness.releaseProviderName();

        Failure failure = failureOf(readLabel(harness.rawService().getMessageHandler(), FakeSecretService.ITEM_PATH));

        assertEquals(Reason.NO_PROVIDER, failure.reason(), "error " + failure.errorName());
    }

    @Test
    void aCallPendingWhenItsConnectionClosesIsDisconnected() throws Exception {
        harness.start(false);
        DBusConnection own = harness.connectAnother();
        MessageHandler handler = new Service(own).getMessageHandler();
        harness.fake().setStallItemProperties(true);

        CompletableFuture<Reply> pending = CompletableFuture.supplyAsync(
                () -> readLabel(handler, FakeSecretService.ITEM_PATH));
        // While the stalled read waits for its reply.
        Thread.sleep(500);
        own.disconnect();

        Failure failure = failureOf(pending.get(20, TimeUnit.SECONDS));
        assertEquals(Reason.DISCONNECTED, failure.reason(),
                "error " + failure.errorName() + ", cause " + failure.cause());
    }

    @Test
    void theSecretOfALockedItemIsLocked() throws Exception {
        harness.start(true);

        Reply reply = harness.rawService().getMessageHandler().sendChecked(Static.Service.SECRETS,
                FakeSecretService.ITEM_PATH, Static.Interfaces.ITEM, "GetSecret", "o",
                harness.session().getSession().getPath());

        assertEquals(Reason.LOCKED, failureOf(reply).reason(), "error " + reply.errorName());
    }
}
