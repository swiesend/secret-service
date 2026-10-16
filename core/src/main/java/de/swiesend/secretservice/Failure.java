package de.swiesend.secretservice;

import de.swiesend.secretservice.handlers.MessageHandler;
import org.freedesktop.dbus.exceptions.FatalDBusException;
import org.freedesktop.dbus.exceptions.NotConnected;

import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.TimeoutException;

/**
 * Why a call failed: the reason, by what a caller can do about it, the library's description, and,
 * when there was one, the D-Bus error name and the exception that ended the call.
 *
 * <p>The message is the library's own, and holds no label and no secret. The text of a D-Bus
 * error, which the provider writes, is logged where the error arrives, and not kept here.</p>
 *
 * @param reason    what failed, by what a caller can do about it
 * @param message   the library's description of the failure
 * @param errorName the name of the D-Bus error that the provider or the bus answered with, or null
 * @param cause     the exception that ended the call, or null
 * @see Result
 * @since 4.0.0
 */
public record Failure(Reason reason, String message, String errorName, Throwable cause) {

    /**
     * What failed, by what a caller can do about it. A later release may add reasons, so a switch
     * over them needs a default branch.
     */
    public enum Reason {
        /**
         * No Secret Service: there is no session bus, or nothing on it provides
         * {@code org.freedesktop.secrets}.
         */
        NO_PROVIDER,
        /**
         * The provider names no default collection: its alias {@code default} points to none, as on
         * an account where nothing has created the login keyring yet.
         */
        NO_DEFAULT_COLLECTION,
        /** The connection closed, or the provider quit or forgot the session, before it answered. */
        DISCONNECTED,
        /** No reply came within the reply timeout, or no answer to a prompt within its timeout. */
        TIMED_OUT,
        /** The item or the collection does not exist. */
        NOT_FOUND,
        /** It stays locked: prompting is disabled, or the provider kept it locked. */
        LOCKED,
        /** The user dismissed the provider's dialog. */
        DISMISSED,
        /** Access was refused, by the consent policy or by the provider. */
        DENIED,
        /** The library refused the call before it sent anything: an empty path, say. */
        INVALID_ARGUMENT,
        /**
         * None of the above: an error that says nothing more, or an answer the library cannot use.
         * The error name and the cause say more.
         */
        OTHER
    }

    public Failure {
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(message, "message must not be null");
    }

    /** A failure without a D-Bus error or an exception. */
    public static Failure of(Reason reason, String message) {
        return new Failure(reason, message, null, null);
    }

    /** A failure that an exception ended, without a D-Bus error. */
    public static Failure of(Reason reason, String message, Throwable cause) {
        return new Failure(reason, message, null, cause);
    }

    /**
     * The failure that a reply without a value stands for: by its outcome, then by the name of its
     * D-Bus error, then, when no answer came, by the exception that ended the call. An error name
     * that says nothing more is {@link Reason#OTHER}.
     *
     * @param reply   a reply whose outcome is not {@link MessageHandler.Outcome#OK OK}
     * @param message the library's description of the failure
     * @throws IllegalArgumentException if the reply's outcome is {@code OK}
     */
    public static Failure from(MessageHandler.Reply reply, String message) {
        Objects.requireNonNull(reply, "reply must not be null");
        Reason reason = switch (reply.outcome()) {
            case OK -> throw new IllegalArgumentException("The reply is no failure: " + message);
            case ABSENT -> Reason.NOT_FOUND;
            case DENIED -> "org.freedesktop.Secret.Error.IsLocked".equals(reply.errorName())
                    ? Reason.LOCKED : Reason.DENIED;
            case UNAVAILABLE -> unavailable(reply);
        };
        return new Failure(reason, message, reply.errorName(), reply.cause());
    }

    private static Reason unavailable(MessageHandler.Reply reply) {
        String name = reply.errorName();
        if (name == null) {
            Throwable cause = reply.cause();
            if (cause instanceof TimeoutException) return Reason.TIMED_OUT;
            if (cause instanceof NotConnected || cause instanceof FatalDBusException) return Reason.DISCONNECTED;
            return Reason.OTHER;
        }
        return switch (name) {
            // From the bus: nothing owns the name, and no service file starts a provider for it.
            case "org.freedesktop.DBus.Error.ServiceUnknown",
                 "org.freedesktop.DBus.Error.NameHasNoOwner" -> Reason.NO_PROVIDER;
            // dbus-java answers a call that is pending when the connection closes with an error
            // named after its IOException.
            case "org.freedesktop.DBus.Local.Disconnected",
                 "org.freedesktop.DBus.Error.Disconnected",
                 "org.freedesktop.Secret.Error.NoSession",
                 "java.io.IOException" -> Reason.DISCONNECTED;
            // From the bus, when the provider quits without replying, or when a reply timeout of
            // the bus's own passes, which a session bus does not set.
            case "org.freedesktop.DBus.Error.NoReply" ->
                    mentionsDisconnect(reply.errorMessage()) ? Reason.DISCONNECTED : Reason.TIMED_OUT;
            case "org.freedesktop.DBus.Error.Timeout",
                 "org.freedesktop.DBus.Error.TimedOut" -> Reason.TIMED_OUT;
            case "org.freedesktop.DBus.Error.AccessDenied" -> Reason.DENIED;
            // From the bus: a service file names a provider, and the provider did not start.
            default -> name.startsWith("org.freedesktop.DBus.Error.Spawn.") ? Reason.NO_PROVIDER : Reason.OTHER;
        };
    }

    // dbus-daemon: "Message recipient disconnected from message bus without replying".
    private static boolean mentionsDisconnect(String errorMessage) {
        return errorMessage != null && errorMessage.toLowerCase(Locale.ROOT).contains("disconnected");
    }
}
