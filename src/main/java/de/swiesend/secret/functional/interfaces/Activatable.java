package de.swiesend.secret.functional.interfaces;

import org.freedesktop.secret.Static;

public enum Activatable {
    DBUS(Static.DBus.Service.DBUS),
    SECRETS(Static.Service.SECRETS),
    GNOME_KEYRING(org.gnome.keyring.Static.Service.KEYRING);

    public final String name;

    Activatable(String name) {
        this.name = name;
    }

}
