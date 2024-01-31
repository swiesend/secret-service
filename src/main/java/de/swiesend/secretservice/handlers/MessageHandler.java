package de.swiesend.secretservice.handlers;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.messages.MethodCall;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Static;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import static de.swiesend.secretservice.Static.DBus.MAX_DELAY_MILLIS;

public class MessageHandler {

    private Logger log = LoggerFactory.getLogger(getClass());

    private DBusConnection connection;

    public MessageHandler(DBusConnection connection) {
        this.connection = connection;
    }

    public Object[] send(String service, String path, String iface, String method, String signature, Object... args) {
        try {
            org.freedesktop.dbus.messages.MessageFactory msgFactory = connection.getMessageFactory();
            org.freedesktop.dbus.messages.Message message = msgFactory.createMethodCall(service, path, iface, method, (byte) 0, signature, args);
            connection.sendMessage(message);

            org.freedesktop.dbus.messages.Message response = ((MethodCall) message).getReply(MAX_DELAY_MILLIS);
            if (log.isTraceEnabled()) log.trace(String.valueOf(response));

            Object[] parameters = null;
            if (response != null) {
                parameters = response.getParameters();
                if (log.isDebugEnabled()) log.debug(Arrays.deepToString(parameters));
            }

            if (response instanceof org.freedesktop.dbus.messages.Error) {
                String error = response.getName();
                switch (error) {
                    case "org.freedesktop.Secret.Error.NoSession":
                    case "org.freedesktop.Secret.Error.NoSuchObject":
                        log.warn(error + ": " + parameters[0]);
                        return null;
                    case "org.gnome.keyring.Error.Denied":
                    case "org.freedesktop.Secret.Error.IsLocked":
                        log.info(error + ": " + parameters[0]);
                        return null;
                    case "org.freedesktop.DBus.Error.NoReply":
                    case "org.freedesktop.DBus.Error.UnknownMethod":
                    case "org.freedesktop.DBus.Error.ServiceUnknown":
                    case "org.freedesktop.dbus.exceptions.NotConnected":
                    case "org.freedesktop.DBus.Local.Disconnected":
                    case "org.freedesktop.dbus.exceptions.FatalDBusException":
                        log.debug(error);
                        return null;
                    default:
                        throw new DBusException(error);
                }
            }

            return parameters;
        } catch (DBusException e) {
            log.error("Unexpected D-Bus response:", e);
        }
        return null;
    }

    public Variant getProperty(String service, String path, String iface, String property) {
        Object[] response = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "Get", "ss", iface, property);
        if (response == null) return null;
        return (Variant) response[0];
    }

    public Variant getAllProperties(String service, String path, String iface) {
        Object[] response = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "GetAll", "ss", iface);
        if (response == null) return null;
        return (Variant) response[0];
    }

    public void setProperty(String service, String path, String iface, String property, Variant value) {
        send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "Set", "ssv", iface, property, value);
    }

    public DBusConnection getConnection() {
        return connection;
    }

}
