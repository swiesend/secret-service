package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.TransportEncryption;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Manages a Secret-Service session on top of a D-Bus session.
 */
public class Session implements SessionInterface {

    private static final Logger log = LoggerFactory.getLogger(Session.class);
    public TransportEncryption.EncryptedSession encryptedSession = null;

    // Copy-on-write: a collection removes itself when it closes, also while close() below closes
    // them all, and on whichever thread closes it.
    private List<CollectionInterface> collections = new java.util.concurrent.CopyOnWriteArrayList<>();
    private UUID id = null;
    private ServiceInterface service = null;

    private boolean isClosed = false;

    private Session(ServiceInterface service, TransportEncryption.EncryptedSession encryptedSession) {
        this.id = UUID.randomUUID();
        this.service = service;
        this.encryptedSession = encryptedSession;
    }

    public static Optional<SessionInterface> open(ServiceInterface service) {
        java.util.Objects.requireNonNull(service, "service must not be null");

        Service dbusService = service.getService();

        return new TransportEncryption(dbusService)
                .initialize()
                .flatMap(initialized -> initialized.openSession())
                .flatMap(opened -> opened.generateSessionKey())
                .map(encryptedSession -> {
                    Session session = new Session(service, encryptedSession);
                    return (SessionInterface) session;
                })
                .or(() -> {
                    log.error("Could not open transport encrypted session.");
                    return Optional.empty();
                });
    }

    @Override
    public TransportEncryption.EncryptedSession getEncryptedSession() {
        return encryptedSession;
    }

    @Override
    public de.swiesend.secretservice.Session getSession() {
        return this.encryptedSession.getSession();
    }

    @Override
    public List<CollectionInterface> getCollections() {
        return this.collections;
    }

    @Override
    public ServiceInterface getService() {
        return service;
    }

    @Override
    public Optional<CollectionInterface> collection(String label, Optional<CharSequence> maybePassword) {
        return Collection.open(label, maybePassword, Optional.of(this))
                .map(collection -> {
                    this.collections.add(collection);
                    return collection;
                });
    }

    @Override
    public Optional<CollectionInterface> collectionById(String id) {
        return Collection.openById(id, Optional.of(this))
                .map(collection -> {
                    this.collections.add(collection);
                    return collection;
                });
    }

    @Override
    public Optional<CollectionInterface> defaultCollection() {
        return Collection.openDefault(Optional.of(this))
                .map(collection -> {
                    this.collections.add(collection);
                    return collection;
                });
    }

    /** Forgets a collection, which {@link Collection#close()} calls: a closed one has nothing to close. */
    void forget(CollectionInterface collection) {
        this.collections.remove(collection);
    }

    @Override
    public void close() throws Exception {
        if (!isClosed) {
            for (CollectionInterface collection : this.collections) {
                collection.close();
            }
            // Erases the transport session key as well as closing the D-Bus session.
            encryptedSession.close();
            // The service keeps the sessions it has to close; this one is closed.
            if (service instanceof SecretService secretService) {
                secretService.unregisterSession(this);
            }
        }
        log.trace("closed session");
        isClosed = true;
    }

    @Override
    public UUID getId() {
        return id;
    }
}
