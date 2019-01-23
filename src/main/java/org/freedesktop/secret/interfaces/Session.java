package org.freedesktop.secret.interfaces;

import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.secret.Static;
import org.freedesktop.secret.handlers.Messaging;

import java.util.List;

@DBusInterfaceName(Static.Interfaces.SESSION)
public abstract class Session extends Messaging implements DBusInterface {
    public Session(DBusConnection connection, List<Class> signals,
                   String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
    }

    abstract public void close();
}
