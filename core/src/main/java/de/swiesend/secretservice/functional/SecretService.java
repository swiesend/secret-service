package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.Pair;
import de.swiesend.secretservice.ProviderDetector;
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
public class SecretService implements ServiceInterface {

    private static final Logger log = LoggerFactory.getLogger(SecretService.class);
    private final Optional<SystemInterface> maybeSystem;
    // Concurrent: a session removes itself when it closes, on whichever thread closes it.
    private Map<UUID, SessionInterface> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    private de.swiesend.secretservice.Service service;
    private boolean isGnomeKeyringAvailable;

    private Duration timeout = DEFAULT_PROMPT_TIMEOUT;

    private boolean isClosed = false;

    private SecretService(SystemInterface system, AvailableServices available, Optional<SystemInterface> maybeSystem) {
        this.maybeSystem = maybeSystem;
        this.service = new Service(system.getConnection());
        // The name is not enough: it is activatable wherever gnome-keyring is installed, also where
        // KeePassXC or KWallet serves org.freedesktop.secrets, and gnome-keyring's own interface is
        // reached through that provider. create() has opened a session before this runs, so the
        // provider is up and its owner can be compared.
        this.isGnomeKeyringAvailable = available.services.contains(Activatable.GNOME_KEYRING)
                && ProviderDetector.detectProvider(system.getConnection()) == ProviderDetector.Provider.GNOME_KEYRING;
    }

    /**
     * Create a Secret-Service instance with initialized transport encryption.
     */
    public static Optional<ServiceInterface> create() {
        Optional<SystemInterface> system = System.connect();
        return create(system);
    }

    /**
     * Create a Secret-Service instance on the given system.
     *
     * <p>The service takes the system over: closing the service closes the system, and so does a
     * {@code create} that finds the service unavailable. To keep a connection open beyond the
     * service, pass {@link System#wrap}.</p>
     */
    public static Optional<ServiceInterface> create(Optional<SystemInterface> maybeSystem) {
        if (maybeSystem == null || maybeSystem.isEmpty()) {
            return Optional.empty();
        }
        SystemInterface system = maybeSystem.get();
        AvailableServices available = new AvailableServices(system);

        if (!ServiceInterface.isAvailable(system, available)) {
            try {
                system.close();
            } catch (Exception e) {
                log.warn("Failed to close system after availability check.", e);
            }
            return Optional.empty();
        }

        return Optional.of(new SecretService(system, available, maybeSystem));
    }

    @Override
    public boolean isGnomeKeyringAvailable() {
        return this.isGnomeKeyringAvailable;
    }

    @Override
    public String getProvider() {
        return detectProvider().displayName;
    }

    @Override
    public de.swiesend.secretservice.ProviderDetector.Provider detectProvider() {
        return maybeSystem
                .map(s -> de.swiesend.secretservice.ProviderDetector.detectProvider(s.getConnection()))
                .orElse(de.swiesend.secretservice.ProviderDetector.Provider.UNAVAILABLE);
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

    /** Forgets a session, which {@link Session#close()} calls: a closed one has nothing to close. */
    void unregisterSession(SessionInterface session) {
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
        if (!isClosed) {
            List<SessionInterface> values = getSessions();
            if (values != null) {
                for (SessionInterface session : values) {
                    unregisterSession(session);
                    session.close();
                }
            }
            // Before the system: on a wrapped connection, which outlives this service, the
            // handlers would otherwise stay registered for the life of the connection.
            service.getSignalHandler().disconnect();
            if (maybeSystem.isPresent()) {
                maybeSystem.get().close();
            }
        }
        log.trace("closed service");
        isClosed = true;
    }

    public de.swiesend.secretservice.Service getService() {
        return service;
    }
}
