package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.Pair;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.functional.interfaces.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;

import static de.swiesend.secretservice.Static.DEFAULT_PROMPT_TIMEOUT;

/**
 * Entrypoint for the functional high-level API. Manages Secret-Service sessions and the D-Bus connection.
 */
public class SecretService extends ServiceInterface {

    private static final Logger log = LoggerFactory.getLogger(SecretService.class);
    private Map<UUID, SessionInterface> sessions = new HashMap<>();
    private de.swiesend.secretservice.Service service;

    private static Optional<SystemInterface> maybeSystem = Optional.empty();

    private boolean isGnomeKeyringAvailable;

    private Duration timeout = DEFAULT_PROMPT_TIMEOUT;

    private SecretService(SystemInterface system, AvailableServices available) {
        this.service = new Service(system.getConnection());
        this.isGnomeKeyringAvailable = available.services.contains(Activatable.GNOME_KEYRING);
    }

    /**
     * Create a Secret-Service instance with initialized transport encryption.
     */
    public static Optional<ServiceInterface> create() {
        maybeSystem = System.connect();
        return create(maybeSystem);
    }

    public static Optional<ServiceInterface> create(Optional<SystemInterface> maybeSystem) {
        return maybeSystem
                .map(system -> new Pair<>(system, new AvailableServices(system)))
                .filter(pair -> isAvailable(pair.a, pair.b))
                .map(pair -> new SecretService(pair.a, pair.b));
    }

    @Override
    public boolean isGnomeKeyringAvailable() {
        return this.isGnomeKeyringAvailable;
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
        List<SessionInterface> values = getSessions();
        if (values != null) {
            for (SessionInterface session : values) {
                unregisterSession(session);
                session.close();
            }
        }
        if (maybeSystem.isPresent()) {
            maybeSystem.get().close();
        }
    }

    public de.swiesend.secretservice.Service getService() {
        return service;
    }
}
