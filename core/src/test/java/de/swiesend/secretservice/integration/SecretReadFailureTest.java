package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.TransportEncryption;
import de.swiesend.secretservice.functional.Collection;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The functional API reports a secret it cannot read as an empty result, also when reading it
 * throws: an exception from {@code getSecrets()} would drop the secrets it had decrypted already,
 * which the caller then cannot erase.
 */
class SecretReadFailureTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    @Test
    void aSecretWhoseReadingThrowsIsReportedAsNone() throws Exception {
        harness.start(false);
        SessionInterface session = withBrokenDecryption(harness.service().openSession().orElseThrow());

        try (CollectionInterface collection = Collection
                .open(FakeSecretService.COLLECTION_LABEL, Optional.empty(), Optional.of(session))
                .orElseThrow()) {
            assertEquals(Optional.empty(), collection.getSecret(FakeSecretService.ITEM_PATH),
                    "no secret, rather than the exception");
            assertEquals(Optional.of(Map.of()), collection.getSecrets(),
                    "the item that could not be read is left out");
        }
    }

    /** {@code real}, except that decrypting a secret throws. */
    private SessionInterface withBrokenDecryption(SessionInterface real) {
        TransportEncryption.EncryptedSession broken =
                new TransportEncryption(harness.service().getService()).new EncryptedSession() {
                    @Override
                    public Optional<char[]> decrypt(Secret secret) {
                        throw new IllegalStateException("broken decryption");
                    }
                };
        return new SessionInterface() {
            @Override public TransportEncryption.EncryptedSession getEncryptedSession() { return broken; }
            @Override public Optional<CollectionInterface> collection(String label, Optional<CharSequence> maybePassword) { return real.collection(label, maybePassword); }
            @Override public Optional<CollectionInterface> collectionById(String id) { return real.collectionById(id); }
            @Override public Optional<CollectionInterface> defaultCollection() { return real.defaultCollection(); }
            @Override public ServiceInterface getService() { return real.getService(); }
            @Override public de.swiesend.secretservice.Session getSession() { return real.getSession(); }
            @Override public List<CollectionInterface> getCollections() { return real.getCollections(); }
            @Override public UUID getId() { return real.getId(); }
            @Override public void close() throws Exception { real.close(); }
        };
    }
}
