package org.freedesktop.secret.interfaces;

import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.secret.Static;

@DBusInterfaceName(Static.Interfaces.SESSION)
public interface Session extends DBusInterface {

    /**
     * Close this session.
     *
     * @return true if closed else false
     */
    boolean close();

}
