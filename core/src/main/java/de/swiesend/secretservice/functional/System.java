package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.exceptions.DBusExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Optional;

/**
 * Manages the D-Bus connection on the system.
 */
public class System implements SystemInterface {

    private static final Logger log = LoggerFactory.getLogger(System.class);

    private final DBusConnection connection;
    private final boolean ownsConnection;
    private boolean disconnected = false;

    private System(DBusConnection connection, boolean ownsConnection) {
        this.connection = connection;
        this.ownsConnection = ownsConnection;
    }

    /**
     * Connect to the session bus. dbus-java shares one connection between every {@code connect()}
     * in the JVM; {@link #close()} gives up this System's share, once, and the last share closes
     * the connection.
     *
     * @return a new SystemInterface or {@code Optional.empty()}
     */
    public static Optional<SystemInterface> connect() {
        try {
            DBusConnection dbus = DBusConnectionBuilder.forSessionBus().build();
            return Optional.of(new System(dbus, true));
        } catch (DBusException | DBusExecutionException | IllegalStateException | IllegalArgumentException e) {
            // Unchecked ones too. Without a session bus address, as over ssh, from cron or in a
            // container, the builder throws AddressResolvingException; for a malformed address,
            // InvalidBusAddressException, an IllegalStateException.
            log.warn(String.format("Could not communicate properly with the D-Bus: [%s]: %s", e.getClass().getSimpleName(), e.getMessage()));
        } catch (ExceptionInInitializerError | NoClassDefFoundError e) {
            // dbus-java's TransportBuilder fails its own static initializer where it finds no
            // transport, as in a shaded jar without the service files, or two of them; after that
            // its class cannot be loaded at all. The service is unavailable then, as without a bus.
            log.warn("No D-Bus transport could be loaded.", e);
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
        java.util.Objects.requireNonNull(connection, "connection must not be null");
        if (!connection.isConnected()) {
            throw new IllegalStateException("Cannot wrap a disconnected DBusConnection.");
        }
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
            // Once. connect() takes dbus-java's shared connection, which every System.connect() in
            // the JVM gets and which counts its holders: each close() gives up one share, and the
            // last share disconnects them all. A second close() here would give up another
            // holder's share.
            if (disconnected) return true;
            disconnected = true;
            try {
                connection.close();
            } catch (IOException e) {
                log.warn("Failed to close D-Bus connection.", e);
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public void close() throws Exception {
        disconnect();
    }
}
