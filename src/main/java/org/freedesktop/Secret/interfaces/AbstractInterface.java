package org.freedesktop.Secret.interfaces;

import org.freedesktop.Secret.handlers.Messaging;
import org.freedesktop.dbus.connections.impl.DBusConnection;

import java.util.List;

abstract public class AbstractInterface extends Messaging {

    public AbstractInterface(DBusConnection connection, List<Class> signals,
                             String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
    }
}
