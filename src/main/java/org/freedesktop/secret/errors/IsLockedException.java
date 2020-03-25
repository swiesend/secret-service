package org.freedesktop.secret.errors;

/**
 * The object must be unlocked before this action can be carried out.
 *
 * <p><code>org.freedesktop.Secret.Error.IsLocked</code></p>
 */
public class IsLockedException extends Exception {
    public IsLockedException() {
    }

    public IsLockedException(String message) {
        super(message);
    }

    public IsLockedException(String message, Throwable cause) {
        super(message, cause);
    }

    public IsLockedException(Throwable cause) {
        super(cause);
    }

    public IsLockedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
