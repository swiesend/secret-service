package org.freedesktop.secret.handlers;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.messages.Message;
import org.freedesktop.dbus.messages.MethodCall;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Static;
import org.freedesktop.secret.errors.IsLockedException;
import org.freedesktop.secret.errors.NoSessionException;
import org.freedesktop.secret.errors.NoSuchObjectException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class MessageHandler {

    private Logger log = LoggerFactory.getLogger(getClass());

    private DBusConnection connection;

    public MessageHandler(DBusConnection connection) {
        this.connection = connection;

        if (this.connection != null) {
            this.connection.setWeakReferences(true);
            Runtime.getRuntime().addShutdownHook(new Thread(() ->
                    this.connection.disconnect()
            ));
        }
    }

    public Object[] send(String service, String path, String iface, String method, String signature, Object... args) throws DBusException {
        try {
            org.freedesktop.dbus.messages.Message message = new MethodCall(
                    service,
                    path,
                    iface,
                    method, (byte) 0, signature, args);

            connection.sendMessage(message);

            Message response = ((MethodCall) message).getReply(2000L);
            if (response != null) {
                log.trace(response.toString());

                if (response instanceof org.freedesktop.dbus.errors.Error) {
                    switch (response.getName()) {
                        case "org.freedesktop.Secret.Error.NoSession":
                            throw new NoSessionException((String) response.getParameters()[0]);
                        case "org.freedesktop.Secret.Error.NoSuchObject":
                            throw new NoSuchObjectException((String) response.getParameters()[0]);
                        case "org.freedesktop.Secret.Error.IsLocked":
                            throw new IsLockedException((String) response.getParameters()[0]);
                        default:
                            throw new DBusException(response.getName() + ": " + response.getParameters()[0]);
                    }
                }

                Object[] parameters = response.getParameters();
                log.debug(Arrays.deepToString(parameters));

                if (parameters != null) {
                    return parameters;
                } else {
                    throw new DBusException("Empty parameters");
                }
            } else {
                throw new DBusException("Empty response");
            }
        } catch (Exception e) {
            throw new DBusException(e.toString(), e.getCause());
        }
    }

    public Variant getProperty(String service, String path, String iface, String property) throws DBusException {
        Object[] response = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "Get", "ss", iface, property);
        try {
            return (Variant) response[0];
        } catch (Exception e) {
            throw new DBusException("Could not get property: {service: " + service + ", path: " + path + ", interface: " + iface + ", property: " + property + "}");
        }
    }

    public Variant getAllProperties(String service, String path, String iface) throws DBusException {
        Object[] response = send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "GetAll", "ss", iface);
        try {
            return (Variant) response[0];
        } catch (Exception e) {
            throw new DBusException("Could not get all properties: {service: " + service + ", path: " + path + ", interface: " + iface + "}");
        }
    }

    public void setProperty(String service, String path, String iface, String property, Variant value) throws DBusException {
        send(service, path, Static.DBus.Interfaces.DBUS_PROPERTIES,
                "Set", "ssv", iface, property, value);
    }

    public DBusConnection getConnection() {
        return connection;
    }

}
