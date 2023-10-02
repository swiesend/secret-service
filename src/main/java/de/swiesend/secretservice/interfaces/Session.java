package de.swiesend.secretservice.interfaces;

import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.interfaces.DBusInterface;
import de.swiesend.secretservice.Static;

@DBusInterfaceName(Static.Interfaces.SESSION)
public interface Session extends DBusInterface {

    /**
     * Close this session.
     */
    abstract public void close();

}
