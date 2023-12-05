package de.swiesend.secretservice.functional.interfaces;

import de.swiesend.secretservice.Static;

public enum Activatable {
    DBUS(Static.DBus.Service.DBUS),
    SECRETS(Static.Service.SECRETS),
    GNOME_KEYRING(de.swiesend.secretservice.gnome.keyring.Static.Service.KEYRING);

    public final String name;

    Activatable(String name) {
        this.name = name;
    }

}
