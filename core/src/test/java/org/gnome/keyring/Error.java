package org.gnome.keyring;

import org.freedesktop.dbus.exceptions.DBusExecutionException;

/**
 * gnome-keyring's own error, for {@code FakeSecretService} to raise. Named for the same reason as
 * {@link org.freedesktop.Secret.Error}: dbus-java sends {@code org.gnome.keyring.Error$Denied} as
 * {@code org.gnome.keyring.Error.Denied}.
 */
public final class Error {

    private Error() {
    }

    /** The master password was wrong. */
    public static final class Denied extends DBusExecutionException {
        public Denied(String message) {
            super(message);
        }
    }
}
