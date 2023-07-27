package de.swiesend.secretservice.functional;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SystemTest {

    System system;

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
        assertTrue(System.isConnected());
    }

    @Test
    void disconnect() {
        assertTrue(system.getConnection().isConnected());
        assertTrue(system.disconnect());
        assertFalse(system.getConnection().isConnected());
    }

    @Test
    void getConnection() {
        DBusConnection connection = system.getConnection();
        assertNotNull(connection);
        assertTrue(connection.isConnected());
    }

}