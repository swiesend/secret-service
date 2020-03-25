package org.freedesktop.secret.errors;

/**
 * The session does not exist.
 *
 * <p><code>org.freedesktop.Secret.Error.NoSession</code></p>
 */
public class NoSessionException extends Exception {
    public NoSessionException() {
    }

    public NoSessionException(String message) {
        super(message);
    }

    public NoSessionException(String message, Throwable cause) {
        super(message, cause);
    }

    public NoSessionException(Throwable cause) {
        super(cause);
    }

    public NoSessionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
