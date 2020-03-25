package org.freedesktop.secret.errors;

/**
 * Indicates that the secret service is not available.
 */
public class SecretServiceUnavailableException extends RuntimeException {

    public SecretServiceUnavailableException() {
    }

    public SecretServiceUnavailableException(String message) {
        super(message);
    }

    public SecretServiceUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecretServiceUnavailableException(Throwable cause) {
        super(cause);
    }

    public SecretServiceUnavailableException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
