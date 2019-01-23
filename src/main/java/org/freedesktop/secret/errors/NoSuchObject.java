package org.freedesktop.secret.errors;

/**
 * No such item or collection exists.
 * <p>
 * org.freedesktop.Secret.Error.NoSuchObject
 */
public class NoSuchObject extends Exception {
    public NoSuchObject() {
    }

    public NoSuchObject(String message) {
        super(message);
    }

    public NoSuchObject(String message, Throwable cause) {
        super(message, cause);
    }

    public NoSuchObject(Throwable cause) {
        super(cause);
    }

    public NoSuchObject(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
