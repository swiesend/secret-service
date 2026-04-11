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
    private final boolean ownsConnection;

    private System(DBusConnection connection, boolean ownsConnection) {
        this.connection = connection;
        this.ownsConnection = ownsConnection;
    }

    /**
     * Create a new D-Bus connection owned by this System instance.
     * The connection will be closed when {@link #close()} is called.
     *
     * @return a new SystemInterface or {@code Optional.empty()}
     */
    public static Optional<SystemInterface> connect() {
        try {
            DBusConnection dbus = DBusConnectionBuilder.forSessionBus().build();
            return Optional.of(new System(dbus, true));
        } catch (DBusException e) {
            log.warn(String.format("Could not communicate properly with the D-Bus: [%s]: %s", e.getClass().getSimpleName(), e.getMessage()));
        }
        return Optional.empty();
    }

    /**
     * Wrap an existing D-Bus connection without taking ownership.
     * Calling {@link #close()} on the returned instance will <b>not</b> disconnect
     * the connection — the caller retains responsibility for the connection lifecycle.
     *
     * <p>This is intended for cases where a shared or static connection is managed
     * externally (e.g., {@code SimpleCollection}'s static connection).</p>
     *
     * @param connection an existing, connected DBusConnection
     * @return a SystemInterface backed by the given connection
     */
    public static SystemInterface wrap(DBusConnection connection) {
        return new System(connection, false);
    }

    public boolean isConnected() {
        return connection != null && connection.isConnected();
    }

    @Override
    public DBusConnection getConnection() {
        return connection;
    }

    synchronized public boolean disconnect() {
        if (ownsConnection) {
            connection.disconnect();
            return !connection.isConnected();
        }
        return false;
    }

    @Override
    public void close() throws Exception {
        if (ownsConnection) {
            disconnect();
        }
    }
}
