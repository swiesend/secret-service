package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SystemTest {

    SystemInterface system;

    @BeforeEach
    void beforeEach() {
        system = System.connect().orElseThrow();
    }

    @AfterEach
    void afterEach() {
        assertDoesNotThrow(() -> system.close());
    }

    @Test
    void connect() {
        assertNotNull(system);
    }

    @Test
    void isConnected() {
        assertTrue(system.isConnected());
    }

    @Test
    void disconnectLeavesTheSharedConnectionToItsOtherHolders() throws Exception {
        // System.connect() gives dbus-java's shared connection, and disconnect() gives up this
        // System's share of it: the connection stays open for the others, the second System here.
        try (SystemInterface other = System.connect().orElseThrow()) {
            assertTrue(system.disconnect());
            assertTrue(system.disconnect(), "a second disconnect gives up no other share");
            assertTrue(other.getConnection().isConnected(), "the other System's share keeps it open");
        }
    }

    @Test
    void getConnection() {
        DBusConnection connection = system.getConnection();
        assertNotNull(connection);
        assertTrue(connection.isConnected());
    }

}