package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * Manages the D-Bus connection on the system.
 */
public class System implements SystemInterface {

    private static final Logger log = LoggerFactory.getLogger(System.class);

    private final DBusConnection connection;

    private System(DBusConnection connection) {
        this.connection = connection;
    }

    /**
     * Try to get a new D-Bus connection.
     *
     * @return a new `DBusConnection` or `Optional.empty()`
     */
    public static Optional<SystemInterface> connect() {
        try {
            DBusConnection dbus = DBusConnectionBuilder.forSessionBus().build();
            return Optional.of(new System(dbus));
        } catch (DBusException e) {
            log.warn(String.format("Could not communicate properly with the D-Bus: [%s]: %s", e.getClass().getSimpleName(), e.getMessage()));
        }
        return Optional.empty();
    }

    public boolean isConnected() {
        return connection != null && connection.isConnected();
    }

    @Override
    public DBusConnection getConnection() {
        return connection;
    }

    synchronized public boolean disconnect() {
        connection.disconnect();
        return !connection.isConnected();
    }

    @Override
    public void close() throws Exception {
        disconnect();
    }
}
