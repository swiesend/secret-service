package org.freedesktop.Secret.errors;

/**
 * The session does not exist.
 * <p>
 * org.freedesktop.Secret.Error.NoSession
 */
public class NoSession extends Exception {
    public NoSession() {
    }

    public NoSession(String message) {
        super(message);
    }

    public NoSession(String message, Throwable cause) {
        super(message, cause);
    }

    public NoSession(Throwable cause) {
        super(cause);
    }

    public NoSession(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
