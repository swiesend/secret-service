package de.swiesend.secretservice.handlers;

import org.apache.commons.lang3.ArrayUtils;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.messages.MethodCall;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Static;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;

import static de.swiesend.secretservice.Static.DBus.MAX_DELAY_MILLIS;

public class MessageHandler {

    private Logger log = LoggerFactory.getLogger(getClass());

    private DBusConnection connection;

    public MessageHandler(DBusConnection connection) {
        this.connection = connection;
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
            if (log.isTraceEnabled()) log.trace(String.valueOf(response));

            Object[] parameters = null;
            if (response != null) {
                parameters = response.getParameters();
                if (log.isDebugEnabled()) log.debug(Arrays.deepToString(parameters));
            }

            if (response instanceof org.freedesktop.dbus.errors.Error) {
                String error = response.getName();
                switch (error) {
                    case "org.freedesktop.Secret.Error.NoSession":
                    case "org.freedesktop.Secret.Error.NoSuchObject":
                        if (ArrayUtils.isEmpty(parameters)) {
                            log.warn(error);
                        } else {
                            log.warn(error + ": " + parameters[0]);
                        }
                        return Optional.empty();
                    case "org.gnome.keyring.Error.Denied":
                    case "org.freedesktop.Secret.Error.IsLocked":
                        if (ArrayUtils.isEmpty(parameters)) {
                            log.info(error);
                        } else {
                            log.info(error + ": " + parameters[0]);
                        }
                        return Optional.empty();
                    case "org.freedesktop.DBus.Error.NoReply":
                    case "org.freedesktop.DBus.Error.UnknownMethod":
                    case "org.freedesktop.DBus.Error.ServiceUnknown":
                    case "org.freedesktop.dbus.exceptions.NotConnected":
                    case "org.freedesktop.DBus.Local.Disconnected":
                    case "org.freedesktop.dbus.exceptions.FatalDBusException":
                        if (log.isDebugEnabled()) log.debug(error);
                        return Optional.empty();
                    default:
                        log.error(error);
                        return Optional.empty();
                }
            }

            return Optional.ofNullable(parameters);
        } catch (DBusException e) {
            log.error("Unexpected D-Bus response:", e);
        }
        return Optional.empty();
    }

    public Optional<Variant> getProperty(String service, String path, String iface, String property) {
        Optional<Object[]> maybeResponse = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "Get", "ss", iface, property);
        if (!maybeResponse.isPresent()) return Optional.empty();
        Object[] response = maybeResponse.get();
        return ArrayUtils.isEmpty(response) ? Optional.empty() : Optional.ofNullable((Variant) response[0]);
    }

    public Optional<Variant> getAllProperties(String service, String path, String iface) {
        Optional<Object[]> maybeResponse = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "GetAll", "ss", iface);
        if (!maybeResponse.isPresent()) return Optional.empty();
        Object[] response = maybeResponse.get();
        return ArrayUtils.isEmpty(response) ? Optional.empty() : Optional.ofNullable((Variant) response[0]);
    }

    public boolean setProperty(String service, String path, String iface, String property, Variant value) {
        Optional<Object[]> maybeResponse = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES, "Set", "ssv", iface, property, value);
        return maybeResponse.isPresent();
    }

}
