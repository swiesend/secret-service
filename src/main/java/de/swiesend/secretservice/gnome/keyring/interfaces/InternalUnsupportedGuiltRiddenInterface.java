package de.swiesend.secretservice.gnome.keyring.interfaces;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Secret;
import java.util.Map;
import java.util.Optional;
@DBusInterfaceName("org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface")
public interface InternalUnsupportedGuiltRiddenInterface extends DBusInterface {
    String INTERNAL_UNSUPPORTED_GUILT_RIDDEN_INTERFACE = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface";
    /**
     * Change the password of a collection.
     * 
     * @param collection    The DBusPath of the collection.
     * @param original      The current password.
     * @param master        The new password.
     */
    boolean changeWithMasterPassword(DBusPath collection, Secret original, Secret master);
     * Toggle the lock of a collection.
     *
     * @return The DBusPath of the collection.
    Optional<DBusPath> changeWithPrompt(DBusPath collection);
     * Create a collection with a password without prompting.
     * @param properties    The properties of the collection.
     * @param master        The password of the collection.
     * @return  The DBusPath of the created collection.
    Optional<DBusPath> createWithMasterPassword(Map<String, Variant> properties, Secret master);
     * Unlock a collection without prompting.
    boolean unlockWithMasterPassword(DBusPath collection, Secret master);
}
