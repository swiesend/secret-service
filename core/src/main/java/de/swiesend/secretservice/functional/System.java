package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.Failure;
import de.swiesend.secretservice.Result;
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
        return connectChecked().value();
    }

    /**
     * As {@link #connect()}, but answering why no connection was made: {@code NO_PROVIDER} when
     * there is no session bus to connect to, with the exception of dbus-java as the cause.
     *
     * @return the system, or the failure
     * @since 4.0.0
     */
    public static Result<SystemInterface> connectChecked() {
        try {
            DBusConnection dbus = DBusConnectionBuilder.forSessionBus().build();
            return Result.ok(new System(dbus, true));
        } catch (DBusException | DBusExecutionException | IllegalStateException | IllegalArgumentException e) {
            // Unchecked ones too. Without a session bus address, as over ssh, from cron or in a
            // container, the builder throws AddressResolvingException; for a malformed address,
            // InvalidBusAddressException, an IllegalStateException.
            log.warn("Could not communicate properly with the D-Bus: [{}]: {}",
                    e.getClass().getSimpleName(), e.getMessage());
            return Result.failed(Failure.of(Failure.Reason.NO_PROVIDER, "Could not connect to the session bus", e));
        }
    }

    /**
     * Wrap an existing D-Bus connection without taking ownership.
     * Calling {@link #close()} on the returned instance will <b>not</b> disconnect
     * the connection — the caller retains responsibility for the connection lifecycle.
     *
     * <p>This is intended for cases where a shared or static connection is managed
     * externally, for example by an application that uses one connection for several
     * services.</p>
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
