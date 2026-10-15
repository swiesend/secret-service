package de.swiesend.secretservice.handlers;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Static;

import java.util.List;
import java.util.Optional;

public abstract class Messaging {

    protected DBusConnection connection;
    protected MessageHandler msg;
    protected SignalHandler sh = new SignalHandler();
    protected String serviceName;
    protected String objectPath;
    protected String interfaceName;

    public Messaging(DBusConnection connection, List<Class<? extends DBusSignal>> signals,
                     String serviceName, String objectPath, String interfaceName) {
        this(new MessageHandler(connection, true), signals, serviceName, objectPath, interfaceName);
    }

    /**
     * As the other constructor, with a message handler that this object shares, and calls on its
     * connection. The objects made with a {@link de.swiesend.secretservice.Service} share its
     * handler, and with it the {@link MessageHandler#setReplyTimeout reply timeout}.
     */
    public Messaging(MessageHandler msg, List<Class<? extends DBusSignal>> signals,
                     String serviceName, String objectPath, String interfaceName) {
        this.connection = msg.getConnection();
        this.msg = msg;
        if (signals != null) {
            // The provider's signals only: see SignalHandler.await.
            this.sh.connect(connection, signals, objectPath, serviceName);
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

    /** As {@link #send(String, String, Object...)}, but reporting why the call yielded nothing. */
    protected MessageHandler.Reply sendChecked(String method, String signature, Object... arguments) {
        return msg.sendChecked(serviceName, objectPath, interfaceName, method, signature, arguments);
    }

    protected Optional<Variant> getProperty(String property) {
        return msg.getProperty(serviceName, objectPath, interfaceName, property);
    }

    /**
     * As {@link #getProperty}, but reporting why the read yielded nothing; see
     * {@link MessageHandler.Outcome}.
     */
    protected MessageHandler.Reply getPropertyChecked(String property) {
        return msg.getPropertyChecked(serviceName, objectPath, interfaceName, property);
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

    public DBusPath getPath() {
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
