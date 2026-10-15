package de.swiesend.secretservice;

import de.swiesend.secretservice.Failure.Reason;
import de.swiesend.secretservice.handlers.MessageHandler.Outcome;
import de.swiesend.secretservice.handlers.MessageHandler.Reply;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.exceptions.NotConnected;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The reason that a reply without a value stands for, and the {@link Result} that carries it.
 * Daemon-free: the replies are built here, as {@code MessageHandler} builds them.
 */
class FailureTest {

    private static Reply error(Outcome outcome, String name) {
        return new Reply(Optional.empty(), outcome, name, null);
    }

    private static Reply error(Outcome outcome, String name, String text) {
        return new Reply(Optional.empty(), outcome, name, text);
    }

    private static Reply unanswered(Throwable cause) {
        return new Reply(Optional.empty(), Outcome.UNAVAILABLE, null, null, cause);
    }

    private static Reason reasonOf(Reply reply) {
        return Failure.from(reply, "test").reason();
    }

    @Test
    void anAbsentObjectIsNotFound() {
        assertEquals(Reason.NOT_FOUND, reasonOf(error(Outcome.ABSENT, "org.freedesktop.Secret.Error.NoSuchObject")));
        assertEquals(Reason.NOT_FOUND, reasonOf(error(Outcome.ABSENT, "org.freedesktop.DBus.Error.UnknownObject")));
    }

    @Test
    void aRefusalIsLockedOnlyWhenTheProviderSaysLocked() {
        assertEquals(Reason.LOCKED, reasonOf(error(Outcome.DENIED, "org.freedesktop.Secret.Error.IsLocked")));
        assertEquals(Reason.DENIED, reasonOf(error(Outcome.DENIED, "org.gnome.keyring.Error.Denied")));
        assertEquals(Reason.DENIED, reasonOf(error(Outcome.UNAVAILABLE, "org.freedesktop.DBus.Error.AccessDenied")));
    }

    @Test
    void aNameThatNothingProvidesIsNoProvider() {
        assertEquals(Reason.NO_PROVIDER, reasonOf(error(Outcome.UNAVAILABLE, "org.freedesktop.DBus.Error.ServiceUnknown")));
        assertEquals(Reason.NO_PROVIDER, reasonOf(error(Outcome.UNAVAILABLE, "org.freedesktop.DBus.Error.NameHasNoOwner")));
    }

    @Test
    void aClosedConnectionOrALostSessionIsDisconnected() {
        assertEquals(Reason.DISCONNECTED, reasonOf(error(Outcome.UNAVAILABLE, "org.freedesktop.DBus.Local.Disconnected")));
        assertEquals(Reason.DISCONNECTED, reasonOf(error(Outcome.UNAVAILABLE, "org.freedesktop.Secret.Error.NoSession")));
        assertEquals(Reason.DISCONNECTED, reasonOf(error(Outcome.UNAVAILABLE, "java.io.IOException", "Disconnecting")));
        assertEquals(Reason.DISCONNECTED, reasonOf(unanswered(new NotConnected("closed"))));
    }

    @Test
    void theBusSaysWhetherAMissingReplyIsATimeoutOrAProviderThatQuit() {
        assertEquals(Reason.DISCONNECTED, reasonOf(error(Outcome.UNAVAILABLE, "org.freedesktop.DBus.Error.NoReply",
                "Message recipient disconnected from message bus without replying")));
        assertEquals(Reason.TIMED_OUT, reasonOf(error(Outcome.UNAVAILABLE, "org.freedesktop.DBus.Error.NoReply",
                "Message did not receive a reply (timeout by message bus)")));
        assertEquals(Reason.TIMED_OUT, reasonOf(error(Outcome.UNAVAILABLE, "org.freedesktop.DBus.Error.NoReply")));
    }

    @Test
    void noReplyWithinTheReplyTimeoutIsTimedOut() {
        TimeoutException cause = new TimeoutException("No reply within 2000ms");
        Failure failure = Failure.from(unanswered(cause), "test");

        assertEquals(Reason.TIMED_OUT, failure.reason());
        assertSame(cause, failure.cause(), "the exception that ended the call stays with the failure");
    }

    @Test
    void anErrorThatSaysNothingMoreIsOther() {
        Failure failure = Failure.from(error(Outcome.UNAVAILABLE, "org.freedesktop.DBus.Error.Failed"), "test");

        assertEquals(Reason.OTHER, failure.reason());
        assertEquals("org.freedesktop.DBus.Error.Failed", failure.errorName(), "the error name stays with the failure");
        assertEquals(Reason.OTHER, reasonOf(unanswered(new DBusException("unexpected"))));
        assertEquals(Reason.OTHER, reasonOf(error(Outcome.UNAVAILABLE, null)));
    }

    @Test
    void aSuccessIsNoFailure() {
        Reply ok = new Reply(Optional.of(new Object[]{true}), Outcome.OK, null, null);
        assertThrows(IllegalArgumentException.class, () -> Failure.from(ok, "test"));
    }

    @Test
    void aFailureHasAReasonAndAMessage() {
        assertThrows(NullPointerException.class, () -> Failure.of(null, "test"));
        assertThrows(NullPointerException.class, () -> Failure.of(Reason.OTHER, null));
        assertThrows(NullPointerException.class, () -> Failure.from(null, "test"));
    }

    @Test
    void aResultHoldsAValueOrAFailure() {
        Result<String> ok = Result.ok("/item/1");
        Result<String> failed = Result.failed(Reason.NOT_FOUND, "no such item");

        assertTrue(ok.isOk());
        assertEquals(Optional.of("/item/1"), ok.value());
        assertEquals(Optional.empty(), ok.failure());
        assertFalse(failed.isOk());
        assertEquals(Optional.empty(), failed.value());
        assertEquals(Optional.of(Reason.NOT_FOUND), failed.reason());

        assertEquals(Optional.of(7), ok.map(String::length).value());
        assertEquals(failed.failure(), failed.map(String::length).failure(), "a failure maps to itself");
        assertEquals(Result.ok(null), Result.<String>ok(null).map(String::length), "nothing to map");
        assertEquals(Optional.of(Reason.DENIED),
                ok.flatMap(path -> Result.failed(Reason.DENIED, "refused")).reason());
    }

    @Test
    void aResultNamesNoValue() {
        Result<String> secret = Result.ok("the-secret");

        assertEquals("Result[ok]", secret.toString());
        assertTrue(Result.failed(Reason.LOCKED, "the item is locked").toString().contains("LOCKED"));
    }
}
