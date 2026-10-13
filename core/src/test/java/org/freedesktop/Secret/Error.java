package org.freedesktop.Secret;

import org.freedesktop.dbus.exceptions.DBusExecutionException;

/**
 * The errors of the Secret Service API, for {@code FakeSecretService} to raise.
 *
 * <p>dbus-java names the D-Bus error that an exported method raises after the Java class of the
 * exception it throws, with {@code $} read as {@code .}. These classes therefore live in this
 * package, under this class: {@code org.freedesktop.Secret.Error$IsLocked} goes out as
 * {@code org.freedesktop.Secret.Error.IsLocked}, the name the specification gives and the library
 * classifies.</p>
 */
public final class Error {

    private Error() {
    }

    /** The object must be unlocked before this action can be carried out. */
    public static final class IsLocked extends DBusExecutionException {
        public IsLocked(String message) {
            super(message);
        }
    }

    /** The session does not exist. */
    public static final class NoSession extends DBusExecutionException {
        public NoSession(String message) {
            super(message);
        }
    }

    /** No such item or collection exists. */
    public static final class NoSuchObject extends DBusExecutionException {
        public NoSuchObject(String message) {
            super(message);
        }
    }
}
