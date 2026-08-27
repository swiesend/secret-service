package de.swiesend.secretservice.handlers;

import de.swiesend.secretservice.Static;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.messages.MessageFactory;
import org.freedesktop.dbus.messages.MethodCall;
import org.freedesktop.dbus.types.Variant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;

import static de.swiesend.secretservice.Static.DBus.MAX_DELAY_MILLIS;

public class MessageHandler {

    private Logger log = LoggerFactory.getLogger(getClass());

    private DBusConnection connection;
    private boolean fireAndForget = true;

    public MessageHandler(DBusConnection connection) {
        this.connection = connection;
    }

    public MessageHandler(DBusConnection connection, boolean fireAndForget) {
        this.connection = connection;
        this.fireAndForget = fireAndForget;
    }

    /**
     * Why a call produced no value. {@link Optional#empty()} alone cannot say, and the difference
     * decides whether a caller may act: code that deletes, overwrites or re-creates on the strength
     * of "not found" must never do so on an {@link #UNAVAILABLE}.
     *
     * <p>The mapping is deliberately conservative. Only errors that <em>unambiguously</em> mean "no
     * such object" become {@link #ABSENT}; everything else, including unrecognised error names,
     * falls through to {@link #UNAVAILABLE}. Providers differ in which errors they raise (this
     * project documents per-provider inconsistency elsewhere), so an unfamiliar reply must degrade
     * to "cannot tell" -- the answer that makes callers fail closed -- rather than be guessed at.</p>
     */
    public enum Outcome {
        /** The call succeeded. */
        OK,
        /** The object provably does not exist: the daemon said so by name. */
        ABSENT,
        /** The object exists but we may not read it (locked, or access denied). */
        DENIED,
        /** No usable answer: no reply, disconnected, or an error that implies nothing. */
        UNAVAILABLE
    }

    /**
     * A reply, the reason it carried no value, and the D-Bus error name behind it.
     *
     * <p>{@code errorName} is null on success. It is kept because the same error means different
     * things depending on the call: see {@link #getPropertyChecked}, where
     * {@code DBus.Error.UnknownMethod} proves the object is gone rather than that the method is
     * missing.</p>
     */
    public record Reply(Optional<Object[]> value, Outcome outcome, String errorName) {
        static Reply ok(Object[] v) { return new Reply(Optional.ofNullable(v), Outcome.OK, null); }
        static Reply failed(Outcome o, String errorName) {
            return new Reply(Optional.empty(), o, errorName);
        }
    }

    public Optional<Object[]> send(String service, String path, String iface, String method, String signature, Object... args) {
        return sendChecked(service, path, iface, method, signature, args).value();
    }

    /**
     * As {@link #send}, but reporting <em>why</em> a call yielded nothing. Prefer this wherever an
     * empty result would otherwise be read as "it is not there".
     */
    public Reply sendChecked(String service, String path, String iface, String method, String signature, Object... args) {
        try {
            MessageFactory msgFactory = connection.getMessageFactory();
            org.freedesktop.dbus.messages.Message message = msgFactory.createMethodCall(
                    service,
                    path,
                    iface,
                    method,
                    (byte) 0,
                    signature,
                    args
            );

            connection.sendMessage(message);

            org.freedesktop.dbus.messages.Message response = ((MethodCall) message).getReply(MAX_DELAY_MILLIS);
            if (log.isTraceEnabled()) log.trace("Response: " + response);

            Object[] parameters = null;
            if (response != null) {
                parameters = response.getParameters();
                if (log.isDebugEnabled())
                    log.debug("Response parameters for method " + iface + "/" + method + ": " + Arrays.deepToString(parameters));
            }

            if (response instanceof org.freedesktop.dbus.messages.Error) {
                String error = response.getName();
                switch (error) {
                    case "org.freedesktop.Secret.Error.NoSuchObject":
                        // The Secret Service naming the object as non-existent is the one reply
                        // that proves absence rather than merely failing to confirm presence.
                        logParameterised(error, parameters, Level.WARN);
                        return Reply.failed(Outcome.ABSENT, error);
                    case "org.freedesktop.DBus.Error.UnknownObject":
                        // Likewise from the bus itself: there is no object at that path.
                        logParameterised(error, parameters, Level.ERROR);
                        return Reply.failed(Outcome.ABSENT, error);
                    case "org.freedesktop.Secret.Error.NoSession":
                        // Our session lapsed. Says nothing about the object.
                        logParameterised(error, parameters, Level.WARN);
                        return Reply.failed(Outcome.UNAVAILABLE, error);
                    case "org.gnome.keyring.Error.Denied":
                    case "org.freedesktop.Secret.Error.IsLocked":
                        // The daemon knew the object well enough to refuse it, so it exists.
                        logParameterised(error, parameters, Level.INFO);
                        return Reply.failed(Outcome.DENIED, error);
                    case "org.freedesktop.DBus.Error.NoReply":
                    case "org.freedesktop.DBus.Error.ServiceUnknown":
                    case "org.freedesktop.DBus.Error.UnknownMethod":
                    case "org.freedesktop.DBus.Error.InvalidArgs":
                    case "org.freedesktop.DBus.Error.Failed":
                        // UnknownMethod/InvalidArgs/Failed are about the CALL, not the object's
                        // existence; NoReply and ServiceUnknown are about the daemon. None of them
                        // license the conclusion "it is not there".
                        logParameterised(error, parameters, Level.ERROR);
                        return Reply.failed(Outcome.UNAVAILABLE, error);
                    case "org.freedesktop.DBus.Local.Disconnected":
                        if (log.isDebugEnabled()) log.debug(error);
                        return Reply.failed(Outcome.UNAVAILABLE, error);
                    default:
                        log.error("Unexpected D-Bus error: \"" + error + "\" with parameters: " + Arrays.deepToString(parameters));
                        return Reply.failed(Outcome.UNAVAILABLE, error);
                }
            } else {
                if (parameters != null && parameters.length == 0)
                    return Reply.ok(new Object[]{true}); // indicate with a boolean that there was no error
                else {
                    return Reply.ok(parameters);
                }
            }
        } catch (org.freedesktop.dbus.exceptions.FatalDBusException e) {
            if (log.isDebugEnabled()) log.debug(e.getClass().getName(), e);
        } catch (DBusException e) {
            log.error("Unexpected D-Bus response: ", e);
        } catch (org.freedesktop.dbus.exceptions.NotConnected e) {
            if (log.isDebugEnabled()) log.debug(e.getClass().getName(), e);
        } catch (RuntimeException e) {
            log.error("Unexpected: ", e);
        }
        // Transport-level failure: we never got an answer, so nothing may be inferred.
        return Reply.failed(Outcome.UNAVAILABLE, null);
    }

    private enum Level { INFO, WARN, ERROR }

    /**
     * Logs an error name with its parameters. Null-safe throughout: the pre-existing
     * {@code NoReply}/{@code Failed} branch read {@code parameters.length} unguarded, so an error
     * reply carrying no parameters raised a NullPointerException from inside the error handler.
     */
    private void logParameterised(String error, Object[] parameters, Level level) {
        String msg;
        if (Static.Utils.isNullOrEmpty(parameters)) {
            msg = error;
        } else if (parameters.length == 1) {
            msg = error + ": \"" + parameters[0] + "\"";
        } else {
            msg = error + ": " + Arrays.deepToString(parameters);
        }
        switch (level) {
            case INFO -> log.info(msg);
            case WARN -> log.warn(msg);
            case ERROR -> log.error(msg);
        }
    }

    public Optional<Variant> getProperty(String service, String path, String iface, String property) {
        return getPropertyChecked(service, path, iface, property).value()
                .filter(r -> !Static.Utils.isNullOrEmpty(r))
                .map(r -> (Variant) r[0]);
    }

    /**
     * As {@link #getProperty}, but reporting why the read yielded nothing -- so a caller can tell
     * "this object is gone" from "I could not reach it". See {@link Outcome}.
     */
    public Reply getPropertyChecked(String service, String path, String iface, String property) {
        Reply reply = sendChecked(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "Get", "ss", iface, property);
        // UnknownMethod means the CALL was unrecognised -- true in general, and why sendChecked maps
        // it to UNAVAILABLE. It is not true for THIS call: every object on the bus implements
        // org.freedesktop.DBus.Properties, so the method cannot be missing from an object that
        // exists. gnome-keyring says exactly this for a deleted item:
        //
        //   org.freedesktop.DBus.Error.UnknownMethod: Object does not exist at path "/.../999999"
        //
        // Without this, ABSENT is unreachable on the library's primary provider and every caller
        // that distinguishes "gone" from "cannot tell" degrades to the fail-closed branch forever.
        if (reply.outcome() == Outcome.UNAVAILABLE
                && "org.freedesktop.DBus.Error.UnknownMethod".equals(reply.errorName())) {
            return Reply.failed(Outcome.ABSENT, reply.errorName());
        }
        return reply;
    }

    public Optional<Variant> getAllProperties(String service, String path, String iface) {
        Optional<Object[]> maybeResponse = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "GetAll", "ss", iface);
        if (!maybeResponse.isPresent()) return Optional.empty();
        Object[] response = maybeResponse.get();
        return Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.ofNullable((Variant) response[0]);
    }

    public boolean setProperty(String service, String path, String iface, String property, Variant value) {
        if (log.isDebugEnabled()) log.debug(iface + "@" + property + " with variant: " + value);
        Optional<Object[]> maybeResponse = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES, "Set", "ssv", iface, property, value);
        if (maybeResponse.isPresent() && !fireAndForget) {
            Optional<Variant> maybePropertyValue = getProperty(service, path, iface, property);
            return value.equals(maybePropertyValue.orElse(null));
        } else {
            return maybeResponse.isPresent();
        }
    }

}
