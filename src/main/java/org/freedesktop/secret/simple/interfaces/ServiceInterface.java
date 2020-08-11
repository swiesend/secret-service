package org.freedesktop.secret.simple.interfaces;

import org.freedesktop.secret.errors.SecretServiceUnavailableException;
import org.freedesktop.secret.simple.SimpleService;
import org.freedesktop.secret.simple.SimpleSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public interface ServiceInterface {

    Logger log = LoggerFactory.getLogger(SimpleService.class);

    /**
     * Creates a SimpleService object.
     *
     * <b>NOTE:</b>
     *   To open a session on the user's default collection call <code>SimpleService.open()</code>.
     *   To open a session on a non default collection call <code>SimpleService.openCollection()</code>.
     */
    static SimpleService create() throws SecretServiceUnavailableException {
        try {
            new SimpleSession().openDefaultCollection();
        } catch (Exception e) {
            log.error(e.toString(), e.getCause());
            throw new SecretServiceUnavailableException("Could not find the secret service. Probably the `gnome-keyring` is not installed on the host or the `gnome-keyring-daemon` is not running.");
        }
        return new SimpleService();
    }

    /**
     * Start a session.
     *
     * @return SimpleSession
     */
    SimpleSession session();

}
