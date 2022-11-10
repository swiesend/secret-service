package de.swiesend.secret.functional.interfaces;

import de.swiesend.secret.functional.System;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public abstract class SystemInterface implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SystemInterface.class);

    public static Optional<System> connect() {
        log.warn("Do not call the interface method, but the implementation.");
        return null;
    }

    synchronized public boolean disconnect() {
        log.warn("Do not call the interface method, but the implementation.");
        return false;
    }

    abstract public DBusConnection getConnection();

}
