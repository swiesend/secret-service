package org.gnome.keyring;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Secret;
import org.freedesktop.secret.Service;
import org.freedesktop.secret.handlers.Messaging;

import java.util.Map;

public class InternalUnsupportedGuiltRiddenInterface extends Messaging implements
        org.gnome.keyring.interfaces.InternalUnsupportedGuiltRiddenInterface {

    public InternalUnsupportedGuiltRiddenInterface(Service service) {
        super(service.getConnection(), null,
                org.freedesktop.secret.Static.Service.SECRETS,
                org.freedesktop.secret.Static.ObjectPaths.SECRETS,
                org.gnome.keyring.Static.Interfaces.INTERNAL_UNSUPPORTED_GUILT_RIDDEN_INTERFACE);
    }

    @Override
    public void changeWithMasterPassword(DBusPath collection, Secret original, Secret master) {
        send("ChangeWithMasterPassword", "o(oayays)(oayays)", collection, original, master);
    }

    @Override
    public ObjectPath changeWithPrompt(DBusPath collection) {
        Object[] response = send("ChangeWithPrompt", "o", collection);
        return (ObjectPath) response[0];
    }

    @Override
    public ObjectPath createWithMasterPassword(Map<String, Variant> properties, Secret master) {
        Object[] response = send("CreateWithMasterPassword", "a{sv}(oayays)", properties, master);
        return (ObjectPath) response[0];
    }

    @Override
    public void unlockWithMasterPassword(DBusPath collection, Secret master) {
        send("UnlockWithMasterPassword", "o(oayays)", collection, master);
    }

    @Override
    public boolean isRemote() {
        return false;
    }

}
