package org.freedesktop.secret.interfaces;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.secret.handlers.Messaging;

import java.util.List;

abstract public class AbstractInterface extends Messaging {

    public AbstractInterface(DBusConnection connection, List<Class> signals,
                             String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
    }
}
