module de.swiesend.secretservice {
    requires java.desktop;
    requires org.freedesktop.dbus;
    requires org.slf4j;
    requires hkdf;

    opens de.swiesend.secretservice to org.freedesktop.dbus;

    exports de.swiesend.secretservice.simple;
    exports org.freedesktop.secret.interfaces;
    exports org.freedesktop.secret.simple.interfaces;
    exports org.gnome.keyring.interfaces;
}