package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A service keeps its sessions, and a session its collections, to close them when it closes. One
 * that its owner has closed already is forgotten: a long-lived service that opens and closes a
 * session per operation would otherwise keep every one of them.
 */
class ClosedObjectsTest {

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
    void aClosedSessionIsForgotten() throws Exception {
        harness.start(false);
        ServiceInterface service = harness.service();
        SessionInterface session = service.openSession().orElseThrow();
        assertTrue(service.getSessions().contains(session), "the precondition: the service keeps the session");

        session.close();

        assertFalse(service.getSessions().contains(session), "the service forgot the closed session");
    }

    @Test
    void aClosedCollectionIsForgotten() throws Exception {
        harness.start(false);
        SessionInterface session = harness.service().openSession().orElseThrow();
        CollectionInterface collection = session
                .collection(FakeSecretService.COLLECTION_LABEL, Optional.empty()).orElseThrow();
        assertTrue(session.getCollections().contains(collection), "the precondition: the session keeps the collection");

        collection.close();

        assertFalse(session.getCollections().contains(collection), "the session forgot the closed collection");
        session.close();
    }
}
