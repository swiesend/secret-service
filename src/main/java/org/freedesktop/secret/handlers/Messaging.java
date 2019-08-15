package org.freedesktop.secret.handlers;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Static;

import java.util.List;

public abstract class Messaging {

    protected DBusConnection connection;
    protected MessageHandler msg;
    protected SignalHandler sh = SignalHandler.getInstance();
    protected String serviceName;
    protected String objectPath;
    protected String interfaceName;

    public Messaging(DBusConnection connection, List<Class<? extends DBusSignal>> signals,
                     String serviceName, String objectPath, String interfaceName) {
        this.connection = connection;
        this.msg = new MessageHandler(connection);
        if (signals != null) {
            this.sh.connect(connection, signals);
        }
        this.serviceName = serviceName;
        this.objectPath = objectPath;
        this.interfaceName = interfaceName;
    }

    protected Object[] send(String method) throws DBusException {
        return msg.send(serviceName, objectPath, interfaceName, method, "");
    }

    protected Object[] send(String method, String signature, Object... arguments) throws DBusException {
        return msg.send(serviceName, objectPath, interfaceName, method, signature, arguments);
    }

    protected Variant getProperty(String property) throws DBusException {
        return msg.getProperty(serviceName, objectPath, interfaceName, property);
    }

    protected Variant getAllProperties() throws DBusException {
        return msg.getAllProperties(serviceName, objectPath, interfaceName);
    }

    protected void setProperty(String property, Variant value) throws DBusException {
        msg.setProperty(serviceName, objectPath, interfaceName, property, value);
    }

    public String getServiceName() {
        return serviceName;
    }

    public String getObjectPath() {
        return objectPath;
    }

    public ObjectPath getPath() {
        return Static.Convert.toObjectPath(objectPath);
    }

    public String getInterfaceName() {
        return interfaceName;
    }

    public MessageHandler getMessageHandler() {
        return msg;
    }

    public SignalHandler getSignalHandler() {
        return sh;
    }

    public DBusConnection getConnection() {
        return connection;
    }

}
