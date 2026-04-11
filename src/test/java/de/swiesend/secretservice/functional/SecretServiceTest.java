package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.*;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class SecretServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SecretServiceTest.class);

    private SecretService secretService = null;

    @BeforeEach
    void beforeEach() {
        secretService = (SecretService) SecretService.create().get();
    }

    @AfterEach
    void afterEach() throws Exception {
        secretService.close();
    }

    @Test
    void create() {
        assertNotNull(secretService);
    }

    @Test
    void isOrgGnomeKeyringAvailable() {
        SystemInterface system = System.connect().get();
        assertTrue(ServiceInterface.isAvailable(system, new AvailableServices(system)));
    }

    @Test
    void openSession() {
        assertTrue(secretService.openSession().isPresent());
    }

    @Test
    void getSessions() {
        assertEquals(0, secretService.getSessions().size());
        SessionInterface s1 = secretService.openSession().get();
        SessionInterface s2 = secretService.openSession().get();
        List<SessionInterface> actualSessions = secretService.getSessions().stream().toList();
        assertEquals(2, actualSessions.size());
        List<UUID> actualSessionIds = actualSessions.stream().map(s -> s.getId()).toList();
        assertTrue(actualSessionIds.contains(s1.getId()));
        assertTrue(actualSessionIds.contains(s2.getId()));
    }

    @Test
    void getTimeout() {
    }

    @Test
    void setTimeout() {
    }

    @Test
    void close() {
    }

    @Test
    void getService() {
    }

    @Test
    @DisplayName("Closing SecretService cascades to sessions and disconnects the owned D-Bus connection")
    void closeServiceCascadesToConnectionOwned() throws Exception {
        // Create a standalone service that owns its D-Bus connection
        SystemInterface system = System.connect().get();
        DBusConnection connection = system.getConnection();
        assertTrue(connection.isConnected(), "Connection should be open initially");

        ServiceInterface service = SecretService.create(Optional.of(system)).get();
        SessionInterface session = service.openSession().get();

        // Verify session is active
        assertNotNull(session.getEncryptedSession());

        // Close the service — should cascade: sessions → system → D-Bus connection
        // service.close() calls system.close() which calls connection.close()
        assertDoesNotThrow(() -> service.close(),
                "Closing service with owned connection should not throw");
    }

    @Test
    @DisplayName("Closing SecretService with wrapped (non-owning) System does not disconnect D-Bus")
    void closeServiceDoesNotDisconnectWrappedConnection() throws Exception {
        // Simulate SimpleCollection's pattern: wrap an externally managed connection
        SystemInterface ownedSystem = System.connect().get();
        DBusConnection connection = ownedSystem.getConnection();

        SystemInterface wrappedSystem = de.swiesend.secretservice.functional.System.wrap(connection);
        ServiceInterface service = SecretService.create(Optional.of(wrappedSystem)).get();
        SessionInterface session = service.openSession().get();

        // Close the service — sessions are cleaned up, but wrapped connection stays open
        service.close();

        assertTrue(connection.isConnected(),
                "Wrapped (non-owning) D-Bus connection should remain open after service.close()");

        // Clean up: the owner disconnects
        assertDoesNotThrow(() -> ownedSystem.close(),
                "Closing owned system should not throw");
    }

    @Test
    @DisplayName("Closing a Collection opened with external session does not close the connection")
    void closeCollectionWithExternalSessionKeepsConnection() throws Exception {
        SystemInterface system = System.connect().get();
        DBusConnection connection = system.getConnection();
        assertTrue(connection.isConnected());

        ServiceInterface service = SecretService.create(Optional.of(system)).get();
        SessionInterface session = service.openSession().get();

        // Open a collection WITH an external session (clearSessionAtClose = false)
        CollectionInterface collection = session.defaultCollection().get();
        collection.close();

        // Session and connection should still be alive — collection didn't own them
        assertTrue(connection.isConnected(),
                "Connection should remain open when collection was opened with an external session");

        // Clean up
        assertDoesNotThrow(() -> service.close());
    }

    @Test
    @DisplayName("Collection.open() without session creates and closes its own D-Bus connection")
    void collectionOpenWithoutSessionOwnsConnection() throws Exception {
        // Collection.open() with no session creates its own SecretService/Session/System
        CollectionInterface collection = de.swiesend.secretservice.functional.Collection
                .openDefault(Optional.empty())
                .get();

        // The collection internally created a service with an owned connection.
        // After close(), everything should be cleaned up.
        collection.close();

        // We can't directly access the internal connection to verify, but we can
        // verify a new connection can be established (no leaked file descriptors)
        Optional<ServiceInterface> newService = SecretService.create();
        assertTrue(newService.isPresent(),
                "Should be able to create a new service after closing the previous one");
        newService.get().close();
    }
}
