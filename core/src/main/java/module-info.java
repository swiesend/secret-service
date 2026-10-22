module de.swiesend.secretservice {
    requires transitive org.freedesktop.dbus;
    requires at.favre.lib.hkdf;
    requires org.slf4j;

    opens de.swiesend.secretservice to org.freedesktop.dbus;

    exports de.swiesend.secretservice;
    exports de.swiesend.secretservice.simple;
    exports de.swiesend.secretservice.interfaces;
    exports de.swiesend.secretservice.functional;
    exports de.swiesend.secretservice.functional.interfaces;
    exports de.swiesend.secretservice.gnome.keyring.interfaces;
    // The low-level implementation of the interface above, which unlocks a collection with its
    // password: a module-path application has no other.
    exports de.swiesend.secretservice.gnome.keyring;
    // Extended or returned by exported classes: the low-level classes extend handlers.Messaging,
    // whose getSignalHandler() and getMessageHandler() return handler types, and SimpleCollection
    // extends the class of the same name in simple.interfaces.
    exports de.swiesend.secretservice.handlers;
    exports de.swiesend.secretservice.simple.interfaces;
}