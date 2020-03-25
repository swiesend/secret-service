package org.freedesktop.secret.errors;

/**
 * No such item or collection exists.
 *
 * <p><code>org.freedesktop.Secret.Error.NoSuchObject</code></p>
 */
public class NoSuchObjectException extends Exception {
    public NoSuchObjectException() {
    }

    public NoSuchObjectException(String message) {
        super(message);
    }

    public NoSuchObjectException(String message, Throwable cause) {
        super(message, cause);
    }

    public NoSuchObjectException(Throwable cause) {
        super(cause);
    }

    public NoSuchObjectException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
