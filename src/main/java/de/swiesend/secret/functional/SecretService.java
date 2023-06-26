package de.swiesend.secret.functional;

import de.swiesend.secret.functional.interfaces.*;
import org.freedesktop.secret.Pair;
import org.freedesktop.secret.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;

import static org.freedesktop.secret.Static.DEFAULT_PROMPT_TIMEOUT;

/**
 * Entrypoint for high-level API. Manages Secret-Service sessions and the D-Bus connection.
 */
public class SecretService extends ServiceInterface {

    private static final Logger log = LoggerFactory.getLogger(SecretService.class);
    private Map<UUID, SessionInterface> sessions = new HashMap<>();
    private org.freedesktop.secret.Service service;

    private boolean gnomeKeyringAvailable;

    private Duration timeout = DEFAULT_PROMPT_TIMEOUT;

    private SecretService(SystemInterface system, AvailableServices available) {
        this.service = new Service(system.getConnection());
        this.gnomeKeyringAvailable = available.services.contains(Activatable.GNOME_KEYRING);
    }

    /**
     * Create a Secret-Service instance with initialized transport encryption.
     */
    public static Optional<ServiceInterface> create() {
        return System.connect()
                .map(system -> new Pair<>(system, new AvailableServices(system)))
                .filter(pair -> isAvailable(pair.a, pair.b))
                .map(pair -> new SecretService(pair.a, pair.b));
    }

    @Override
    public boolean isOrgGnomeKeyringAvailable() {
        return this.gnomeKeyringAvailable;
    }

    @Override
    public boolean clear() {
        // TODO: implement
        return false;
    }

    @Override
    public Optional<SessionInterface> openSession() {
        Optional<SessionInterface> session = Session
                .open(this)
                .map(s -> {
                    registerSession(s);
                    return s;
                });
        return session;
    }

    private void registerSession(SessionInterface session) {
        this.sessions.put(session.getId(), session);
    }

    private void unregisterSession(SessionInterface session) {
        this.sessions.remove(session.getId());
    }

    @Override
    public List<SessionInterface> getSessions() {
        return this.sessions.values().stream().toList();
    }

    @Override
    public Duration getTimeout() {
        return timeout;
    }

    @Override
    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
    }

    @Override
    public void close() throws Exception {
        this.clear();
        List<SessionInterface> values = getSessions();
        if (values != null) {
            for (SessionInterface session : values) {
                unregisterSession(session);
                session.close();
            }
        }
    }

    public Service getService() {
        return service;
    }
}
