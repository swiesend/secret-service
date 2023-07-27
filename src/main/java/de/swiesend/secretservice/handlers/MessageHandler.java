package de.swiesend.secretservice.handlers;

import de.swiesend.secretservice.Static;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
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

    public Optional<Object[]> send(String service, String path, String iface, String method, String signature, Object... args) {
        try {
            org.freedesktop.dbus.messages.Message message = new MethodCall(
                    service,
                    path,
                    iface,
                    method, (byte) 0, signature, args);

            connection.sendMessage(message);

            org.freedesktop.dbus.messages.Message response = ((MethodCall) message).getReply(MAX_DELAY_MILLIS);
            if (log.isTraceEnabled()) log.trace("Response: " + response);

            Object[] parameters = null;
            if (response != null) {
                parameters = response.getParameters();
                if (log.isDebugEnabled())
                    log.debug("Response parameters for method " + iface + "/" + method + ": " + Arrays.deepToString(parameters));
            }

            if (response instanceof org.freedesktop.dbus.errors.Error) {
                String error = response.getName();
                switch (error) {
                    case "org.freedesktop.Secret.Error.NoSession":
                    case "org.freedesktop.Secret.Error.NoSuchObject":
                        if (Static.Utils.isNullOrEmpty(parameters)) {
                            log.warn(error);
                        } else {
                            if (parameters.length == 1) {
                                log.warn(error + ": \"" + parameters[0] + "\"");
                            } else {
                                log.warn(error + ": " + Arrays.deepToString(parameters));
                            }
                        }
                        return Optional.empty();
                    case "org.gnome.keyring.Error.Denied":
                    case "org.freedesktop.Secret.Error.IsLocked":
                        if (Static.Utils.isNullOrEmpty(parameters)) {
                            log.info(error);
                        } else {
                            if (parameters.length == 1) {
                                log.info(error + ": \"" + parameters[0] + "\"");
                            } else {
                                log.info(error + ": " + Arrays.deepToString(parameters));
                            }
                        }
                        return Optional.empty();
                    case "org.freedesktop.DBus.Error.NoReply":
                    case "org.freedesktop.DBus.Error.ServiceUnknown":
                    case "org.freedesktop.DBus.Error.UnknownMethod":
                    case "org.freedesktop.DBus.Error.UnknownObject":
                    case "org.freedesktop.DBus.Error.InvalidArgs":
                    case "org.freedesktop.DBus.Error.Failed":
                        if (parameters.length == 1) {
                            log.error(error + ": \"" + parameters[0] + "\"");
                        } else {
                            log.error(error + ": " + Arrays.deepToString(parameters));
                        }
                    case "org.freedesktop.DBus.Local.Disconnected":
                    case "org.freedesktop.dbus.exceptions.FatalDBusException":
                    case "org.freedesktop.dbus.exceptions.NotConnected":
                        if (log.isDebugEnabled()) log.debug(error);
                        return Optional.empty();
                    default:
                        log.error("Unexpected org.freedesktop.dbus.errors.Error: \"" + error + "\" with parameters: " + Arrays.deepToString(parameters));
                        return Optional.empty();
                }
            }
            return Optional.ofNullable(parameters);
        } catch (DBusException e) {
            log.error("Unexpected D-Bus response: ", e);
        } catch (RuntimeException e) {
            log.error("Unexpected: ", e);
        }
        return Optional.empty();
    }

    public Optional<Variant> getProperty(String service, String path, String iface, String property) {
        Optional<Object[]> maybeResponse = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "Get", "ss", iface, property);
        if (!maybeResponse.isPresent()) return Optional.empty();
        Object[] response = maybeResponse.get();
        return Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.ofNullable((Variant) response[0]);
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
