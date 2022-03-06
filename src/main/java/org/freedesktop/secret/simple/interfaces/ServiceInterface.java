package org.freedesktop.secret.simple.interfaces;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Optional;

public abstract class ServiceInterface implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(ServiceInterface.class);

    public abstract Optional<Boolean> clear();

    public static Optional<ServiceInterface> create() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    synchronized public static Optional<Boolean> disconnect() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.of(false);
    }

    private static Optional<DBusConnection> getConnection() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    public static Optional<Boolean> isAvailable() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.of(false);
    }

    public static Optional<Boolean> isConnected() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.of(false);
    }

    abstract Optional<SessionInterface> session();

    private static Optional<Thread> setupShutdownHook() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    public abstract Duration getTimeout();

    public abstract void setTimeout(Duration timeout);

}
