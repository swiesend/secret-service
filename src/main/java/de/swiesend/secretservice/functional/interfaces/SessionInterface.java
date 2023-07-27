package de.swiesend.secretservice.functional.interfaces;

import de.swiesend.secretservice.TransportEncryption;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SessionInterface extends AutoCloseable {

    Optional<CollectionInterface> collection(String label, Optional<CharSequence> maybePassword);

    Optional<CollectionInterface> defaultCollection();

    TransportEncryption.EncryptedSession getEncryptedSession();

    ServiceInterface getService();

    de.swiesend.secretservice.Session getSession();

    List<CollectionInterface> getCollections();

    UUID getId();

}
