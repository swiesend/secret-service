package de.swiesend.secret.functional;

import de.swiesend.secret.functional.interfaces.CollectionInterface;
import de.swiesend.secret.functional.interfaces.ServiceInterface;
import de.swiesend.secret.functional.interfaces.SessionInterface;
import org.freedesktop.secret.Service;
import org.freedesktop.secret.TransportEncryption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

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
    public org.freedesktop.secret.Session getSession() {
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
    public boolean clear() {
        // TODO: to be implemented
        return false;
    }

    @Override
    public Optional<CollectionInterface> collection(String label, CharSequence password) {
        CollectionInterface collection = new Collection(this, label, password);
        this.collections.add(collection);
        return Optional.of(collection);
    }

    @Override
    public Optional<CollectionInterface> defaultCollection() {
        CollectionInterface collection = new Collection(this);
        this.collections.add(collection);
        return Optional.of(collection);
    }

    @Override
    public void close() throws Exception {
        for (CollectionInterface collection : this.collections) {
            collection.close();
        }
    }

    @Override
    public UUID getId() {
        return id;
    }
}
