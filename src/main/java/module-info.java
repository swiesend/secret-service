module de.swiesend.secretservice {
    requires java.desktop;
    requires org.freedesktop.dbus;
    requires org.slf4j;
    requires at.favre.lib.hkdf;

    opens de.swiesend.secretservice to org.freedesktop.dbus;

    exports de.swiesend.secretservice;
    exports de.swiesend.secretservice.simple;
    exports de.swiesend.secretservice.interfaces;
    exports de.swiesend.secretservice.gnome.keyring.interfaces;
}