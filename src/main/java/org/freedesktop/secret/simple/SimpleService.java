package org.freedesktop.secret.simple;

import org.freedesktop.secret.errors.SecretServiceUnavailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The <code>SimpleService</code> is a <code>SimpleSession</code> factory.
 */
public class SimpleService {

    private static final Logger log = LoggerFactory.getLogger(SimpleService.class);

    /**
     * Creates a SimpleService object.
     * <br>
     * <br>
     * <b>NOTE:</b>
     *   To open a session on the user's default collection call <code>SimpleService.open()</code>.
     *   To open a session on a non default collection call <code>SimpleService.openCollection()</code>.
     */
    public static SimpleService create() {
        try {
            new SimpleSession().openDefaultCollection();
        } catch (Exception e) {
            log.error(e.toString(), e.getCause());
            throw new SecretServiceUnavailableException("Could not find the secret service. Probably the `gnome-keyring` is not installed on the host or the `gnome-keyring-daemon` is not running.");
        }
        return new SimpleService();
    }

    public SimpleSession createSession() {
        return new SimpleSession();
    }

}
