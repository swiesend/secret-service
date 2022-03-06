package de.swiesend.secretservice.handlers;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Static;

import java.util.List;
import java.util.Optional;

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

    protected Optional<Object[]> send(String method) {
        return msg.send(serviceName, objectPath, interfaceName, method, "");
    }

    protected Optional<Object[]> send(String method, String signature, Object... arguments) {
        return msg.send(serviceName, objectPath, interfaceName, method, signature, arguments);
    }

    protected Optional<Variant> getProperty(String property) {
        return msg.getProperty(serviceName, objectPath, interfaceName, property);
    }

    protected Optional<Variant> getAllProperties() {
        return msg.getAllProperties(serviceName, objectPath, interfaceName);
    }

    protected boolean setProperty(String property, Variant value) {
        return msg.setProperty(serviceName, objectPath, interfaceName, property, value);
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
