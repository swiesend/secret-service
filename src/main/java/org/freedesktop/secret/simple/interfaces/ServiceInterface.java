package org.freedesktop.secret.simple.interfaces;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Optional;

public abstract class ServiceInterface implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(ServiceInterface.class);

    public static Optional<ServiceInterface> create() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    synchronized public static boolean disconnect() {
        log.warn("Do not call the interface method, but the implementation.");
        return false;
    }

    private static Optional<DBusConnection> getConnection() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    public static boolean isAvailable() {
        log.warn("Do not call the interface method, but the implementation.");
        return false;
    }

    public static boolean isConnected() {
        log.warn("Do not call the interface method, but the implementation.");
        return false;
    }

    private static Optional<Thread> setupShutdownHook() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    public abstract boolean clear();

    public abstract Optional<SessionInterface> getSession();

    public abstract Duration getTimeout();

    public abstract void setTimeout(Duration timeout);

}
