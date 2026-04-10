package de.swiesend.secretservice.functional.interfaces;

import org.freedesktop.dbus.connections.impl.DBusConnection;

public interface SystemInterface extends AutoCloseable {

    DBusConnection getConnection();

    boolean disconnect();

}
