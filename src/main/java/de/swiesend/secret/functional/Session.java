package de.swiesend.secret.functional;

import de.swiesend.secret.functional.interfaces.ServiceInterface;
import org.freedesktop.secret.TransportEncryption;
import de.swiesend.secret.functional.interfaces.CollectionInterface;
import de.swiesend.secret.functional.interfaces.SessionInterface;
import org.freedesktop.secret.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.UUID;

public class Session implements SessionInterface {

    private static final Logger log = LoggerFactory.getLogger(Session.class);

    @Override
    public TransportEncryption.EncryptedSession getEncryptedSession() {
        return encryptedSession;
    }

    public TransportEncryption.EncryptedSession encryptedSession = null;

    private UUID id = null;

    @Override
    public org.freedesktop.secret.Session getSession() {
        return session;
    }

    org.freedesktop.secret.Session session = null;

    @Override
    public ServiceInterface getService() {
        return service;
    }

    private ServiceInterface service = null;

    private Session(ServiceInterface service, TransportEncryption.EncryptedSession encryptedSession) {
        this.id = UUID.randomUUID();
        this.service = service;
        this.encryptedSession = encryptedSession;
        this.session = service.getService().getSession();
    }

    public static Optional<Session> open(ServiceInterface service) {

        Service dbusService = service.getService();

        return new TransportEncryption(dbusService)
                .initialize()
                .flatMap(initialized -> initialized.openSession())
                .flatMap(opened -> opened.generateSessionKey())
                .map(encryptedSession -> {
                    Session session = new Session(service, encryptedSession);
                    service.registerSession(session);
                    return session;
                })
                .or(() -> {
                    log.error("Could not open transport encrypted session.");
                    return Optional.empty();
                });
    }

    @Override
    public boolean clear() {
        // TODO: to be implemented
        return false;
    }

    @Override
    public Optional<CollectionInterface> collection(String label, CharSequence password) {
        return Optional.of(new Collection(this, label, password));
    }

    @Override
    public Optional<CollectionInterface> defaultCollection() {
        return Optional.of(new Collection(this));
    }

    @Override
    public void close() {

    }

    public UUID getId() {
        return id;
    }
}
