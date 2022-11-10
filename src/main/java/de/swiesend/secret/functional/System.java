package de.swiesend.secret.functional;

import de.swiesend.secret.functional.interfaces.SystemInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class System extends SystemInterface {

    private static final Logger log = LoggerFactory.getLogger(System.class);

    private static DBusConnection connection = null;

    private System(DBusConnection connection) {
        this.connection = connection;
    }

    /**
     * Try to get a new DBus connection.
     *
     * @return a new DBusConnection or Optional.empty()
     */
    public static Optional<System> connect() {
        try {
            DBusConnection dbus = DBusConnection.newConnection(DBusConnection.DBusBusType.SESSION);
            System c = new System(dbus);
            return Optional.of(c);
        } catch (DBusException e) {
            if (e == null) {
                log.warn("Could not communicate properly with the D-Bus.");
            } else {
                log.warn(String.format("Could not communicate properly with the D-Bus: [%s]: %s", e.getClass().getSimpleName(), e.getMessage()));
            }
        }
        return Optional.empty();
    }

    public static boolean isConnected() {
        if (connection == null) {
            return false;
        } else {
            return connection.isConnected();
        }
    }

    @Override
    public DBusConnection getConnection() {
        return connection;
    }

    synchronized public boolean disconnect() {
        connection.disconnect();
        return connection.isConnected();
    }

    /*private static Optional<Thread> setupShutdownHook() {
        return Optional.empty();
    }*/
    @Override
    public void close() throws Exception {
        connection.close();
    }
}
