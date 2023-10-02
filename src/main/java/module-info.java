module de.swiesend.secretservice {
    requires transitive org.freedesktop.dbus;
    requires at.favre.lib.hkdf;
    requires org.slf4j;

    opens de.swiesend.secretservice to org.freedesktop.dbus;

    exports de.swiesend.secretservice;
    exports de.swiesend.secretservice.simple;
    exports de.swiesend.secretservice.interfaces;
    exports de.swiesend.secretservice.gnome.keyring.interfaces;
}