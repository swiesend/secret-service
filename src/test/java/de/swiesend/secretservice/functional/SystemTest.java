package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
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
        assertTrue(System.isConnected());
    }

    @Test
    @Disabled
    void disconnect() throws InterruptedException {
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