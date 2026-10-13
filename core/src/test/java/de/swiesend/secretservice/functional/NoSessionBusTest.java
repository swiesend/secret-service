package de.swiesend.secretservice.functional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Without a usable session bus, as over ssh, from cron or in a container, the functional API
 * reports the service as unavailable, as its contract says, instead of throwing. dbus-java signals
 * an address it cannot resolve or parse with unchecked exceptions, and they escaped.
 *
 * <p>dbus-java reads the address from the {@code DBUS_SESSION_BUS_ADDRESS} system property before
 * the environment, which lets a test give it one that cannot work.</p>
 */
class NoSessionBusTest {

    private static final String ADDRESS = "DBUS_SESSION_BUS_ADDRESS";
    private String saved;

    @BeforeEach
    void save() {
        saved = java.lang.System.getProperty(ADDRESS);
    }

    @AfterEach
    void restore() {
        if (saved == null) {
            java.lang.System.clearProperty(ADDRESS);
        } else {
            java.lang.System.setProperty(ADDRESS, saved);
        }
    }

    @Test
    void anAddressNoTransportServesIsUnavailable() {
        // TCP: no TCP transport is on the class path, so dbus-java throws AddressResolvingException.
        java.lang.System.setProperty(ADDRESS, "tcp:host=localhost,port=1");

        assertTrue(System.connect().isEmpty());
        assertTrue(SecretService.create().isEmpty());
    }

    @Test
    void aMalformedAddressIsUnavailable() {
        java.lang.System.setProperty(ADDRESS, "not an address");

        assertTrue(System.connect().isEmpty());
        assertTrue(SecretService.create().isEmpty());
    }
}
