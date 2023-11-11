package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.TransportEncryption;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Manages a Secret-Service session on top of a D-Bus session.
 */
public class Session implements SessionInterface {

    private static final Logger log = LoggerFactory.getLogger(Session.class);
    public TransportEncryption.EncryptedSession encryptedSession = null;

    private List<CollectionInterface> collections = new ArrayList<>();
    private UUID id = null;
    private ServiceInterface service = null;

    private Session(ServiceInterface service, TransportEncryption.EncryptedSession encryptedSession) {
        this.id = UUID.randomUUID();
        this.service = service;
        this.encryptedSession = encryptedSession;
    }

    public static Optional<SessionInterface> open(ServiceInterface service) {

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
        CollectionInterface collection = new Collection(label, maybePassword, Optional.of(this));
        this.collections.add(collection);
        return Optional.of(collection);
    }

    @Override
    public Optional<CollectionInterface> defaultCollection() {
        CollectionInterface collection = new Collection(Optional.of(this));
        this.collections.add(collection);
        return Optional.of(collection);
    }

    @Override
    public void close() throws Exception {
        for (CollectionInterface collection : this.collections) {
            collection.close();
        }
        encryptedSession.getSession().close();
    }

    @Override
    public UUID getId() {
        return id;
    }
}
