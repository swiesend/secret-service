package org.freedesktop.secret.handlers;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.messages.MethodCall;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Static;
import org.freedesktop.secret.errors.IsLocked;
import org.freedesktop.secret.errors.NoSession;
import org.freedesktop.secret.errors.NoSuchObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import static org.freedesktop.secret.Static.DBus.MAX_DELAY_MILLIS;

public class MessageHandler {

    private Logger log = LoggerFactory.getLogger(getClass());

    private DBusConnection connection;

    public MessageHandler(DBusConnection connection) {
        this.connection = connection;
    }

    public Object[] send(String service, String path, String iface, String method, String signature, Object... args) {
        try {
            org.freedesktop.dbus.messages.Message message = new MethodCall(
                    service,
                    path,
                    iface,
                    method, (byte) 0, signature, args);

            connection.sendMessage(message);

            org.freedesktop.dbus.messages.Message response = ((MethodCall) message).getReply(MAX_DELAY_MILLIS);
            if (log.isTraceEnabled()) log.trace(String.valueOf(response));

            if (response instanceof org.freedesktop.dbus.errors.Error) {
                switch (response.getName()) {
                    case "org.freedesktop.Secret.Error.NoSession":
                        throw new NoSession((String) response.getParameters()[0]);
                    case "org.freedesktop.Secret.Error.NoSuchObject":
                        throw new NoSuchObject((String) response.getParameters()[0]);
                    case "org.freedesktop.Secret.Error.IsLocked":
                        throw new IsLocked((String) response.getParameters()[0]);
                    case "org.freedesktop.DBus.Error.NoReply":
                        log.warn("org.freedesktop.DBus.Error.NoReply");
                        break;
                    default:
                        throw new DBusException(response.getName() + ": " + response.getParameters()[0]);
                }
            }

            Object[] parameters = response.getParameters();
            log.debug(Arrays.deepToString(parameters));
            return parameters;
        } catch (NoSession | NoSuchObject | IsLocked | DBusException e) {
            log.error("D-Bus response:", e);
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
