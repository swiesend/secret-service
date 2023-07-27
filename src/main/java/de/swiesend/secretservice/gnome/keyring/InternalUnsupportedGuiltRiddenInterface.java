package de.swiesend.secretservice.gnome.keyring;

import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.handlers.Messaging;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.types.Variant;

import java.util.Map;
import java.util.Optional;

public class InternalUnsupportedGuiltRiddenInterface extends Messaging implements
        de.swiesend.secretservice.gnome.keyring.interfaces.InternalUnsupportedGuiltRiddenInterface {

    public InternalUnsupportedGuiltRiddenInterface(Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS,
                INTERNAL_UNSUPPORTED_GUILT_RIDDEN_INTERFACE);
    }

    @Override
    public boolean changeWithMasterPassword(DBusPath collection, Secret original, Secret master) {
        return send("ChangeWithMasterPassword", "o(oayays)(oayays)", collection, original, master)
                .map(response -> (boolean) response[0]) // expect first parameter to be true when no error is present
                .orElse(false);
    }

    @Override
    public Optional<ObjectPath> changeWithPrompt(DBusPath collection) {
        return send("ChangeWithPrompt", "o", collection)
                .flatMap(response -> Static.Convert.toObjectPath(response[0]));
    }

    @Override
    public Optional<ObjectPath> createWithMasterPassword(Map<String, Variant> properties, Secret master) {
        return send("CreateWithMasterPassword", "a{sv}(oayays)", properties, master)
                .flatMap(response -> Static.Convert.toObjectPath(response[0]));
    }

    @Override
    public boolean unlockWithMasterPassword(DBusPath collection, Secret master) {
        return send("UnlockWithMasterPassword", "o(oayays)", collection, master)
                .map(response -> (boolean) response[0]) // expect first parameter to be true when no error is present
                .orElse(false);
    }

    @Override
    public boolean isRemote() {
        return false;
    }

}
