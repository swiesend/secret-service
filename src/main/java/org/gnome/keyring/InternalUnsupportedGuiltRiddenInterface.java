package org.gnome.keyring;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Secret;
import org.freedesktop.secret.Service;
import org.freedesktop.secret.Static;
import org.freedesktop.secret.handlers.Messaging;

import java.util.Map;
import java.util.Optional;

import static org.freedesktop.secret.Static.Convert.toObjectPath;

public class InternalUnsupportedGuiltRiddenInterface extends Messaging implements
        org.gnome.keyring.interfaces.InternalUnsupportedGuiltRiddenInterface {

    public InternalUnsupportedGuiltRiddenInterface(Service service) {
        super(service.getConnection(), null,
                org.freedesktop.secret.Static.Service.SECRETS,
                org.freedesktop.secret.Static.ObjectPaths.SECRETS,
                INTERNAL_UNSUPPORTED_GUILT_RIDDEN_INTERFACE);
    }

    @Override
    public boolean changeWithMasterPassword(DBusPath collection, Secret original, Secret master) {
        return send("ChangeWithMasterPassword", "o(oayays)(oayays)", collection, original, master)
                // TODO: check which condition should apply
                // .map(Static.Utils::isNullOrEmpty)
                .map(response -> !Static.Utils.isNullOrEmpty(response))
                .orElse(false);
    }

    @Override
    public Optional<ObjectPath> changeWithPrompt(DBusPath collection) {
        return send("ChangeWithPrompt", "o", collection)
                .flatMap(response -> toObjectPath(response[0]));
    }

    @Override
    public Optional<ObjectPath> createWithMasterPassword(Map<String, Variant> properties, Secret master) {
        return send("CreateWithMasterPassword", "a{sv}(oayays)", properties, master)
                .flatMap(response -> toObjectPath(response[0]));
    }

    @Override
    public boolean unlockWithMasterPassword(DBusPath collection, Secret master) {
        return send("UnlockWithMasterPassword", "o(oayays)", collection, master)
                // TODO: check which condition should apply
                // .map(Static.Utils::isNullOrEmpty)
                .map(response -> !Static.Utils.isNullOrEmpty(response))
                .orElse(false);
    }

    @Override
    public boolean isRemote() {
        return false;
    }

}
