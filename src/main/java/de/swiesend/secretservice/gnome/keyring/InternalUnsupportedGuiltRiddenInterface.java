package de.swiesend.secretservice.gnome.keyring;

import de.swiesend.secretservice.Static;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.handlers.Messaging;

import java.util.Map;

public class InternalUnsupportedGuiltRiddenInterface extends Messaging implements
        de.swiesend.secretservice.gnome.keyring.interfaces.InternalUnsupportedGuiltRiddenInterface {

    public InternalUnsupportedGuiltRiddenInterface(Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS,
                INTERNAL_UNSUPPORTED_GUILT_RIDDEN_INTERFACE);
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
