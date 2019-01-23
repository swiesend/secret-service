package org.gnome.keyring.interfaces;

import org.freedesktop.Secret.Secret;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.types.Variant;

import java.util.Map;

@DBusInterfaceName("org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface")
public interface InternalUnsupportedGuiltRiddenInterface extends DBusInterface {

    public void changeWithMasterPassword(DBusPath collection, Secret original, Secret master);

    public ObjectPath changeWithPrompt(DBusPath collection);

    public ObjectPath createWithMasterPassword(Map<String, Variant> properties, Secret master);

    public void unlockWithMasterPassword(DBusPath collection, Secret master);

}
