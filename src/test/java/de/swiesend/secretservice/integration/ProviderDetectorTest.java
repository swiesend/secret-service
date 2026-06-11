package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.ProviderDetector;
import de.swiesend.secretservice.ProviderDetector.Provider;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link ProviderDetector}. The pure-enum invariants and the
 * null/disconnected guards run without a bus; the live-detection test connects to
 * the session bus the same way {@code Context} does and asserts the detector
 * resolves a known provider (gnome-keyring in CI).
 */
class ProviderDetectorTest {

    private static final Logger log = LoggerFactory.getLogger(ProviderDetectorTest.class);

    @Test
    void detectProviderNullConnection() {
        assertEquals(Provider.UNAVAILABLE, ProviderDetector.detectProvider(null));
        assertEquals(Provider.UNAVAILABLE.displayName, ProviderDetector.detect(null));
    }

    @Test
    void detectProviderDisconnectedConnection() throws Exception {
        DBusConnection connection = DBusConnectionBuilder.forSessionBus().withShared(false).build();
        connection.disconnect();
        // A disconnected connection must resolve to UNAVAILABLE, never throw.
        assertEquals(Provider.UNAVAILABLE, ProviderDetector.detectProvider(connection));
    }

    @Test
    void knownProvidersDeclareBusNames() {
        for (Provider p : new Provider[]{Provider.KEEPASSXC, Provider.GNOME_KEYRING, Provider.KWALLET}) {
            assertNotNull(p.displayName, "displayName must not be null for " + p);
            assertFalse(p.displayName.isBlank(), "displayName must not be blank for " + p);
            assertTrue(p.busNames.length > 0, "known provider " + p + " must declare bus names");
        }
        // The sentinel providers carry a display name but no well-known bus names.
        assertEquals(0, Provider.UNKNOWN.busNames.length);
        assertEquals(0, Provider.UNAVAILABLE.busNames.length);
    }

    @Test
    void detectLiveProvider() throws Exception {
        DBusConnection connection = DBusConnectionBuilder.forSessionBus().withShared(false).build();
        try {
            Provider provider = ProviderDetector.detectProvider(connection);
            log.info("Detected live Secret Service provider: {}", provider);

            // org.freedesktop.secrets is present in the test environment, so detection
            // must resolve to a concrete, available provider (provider-agnostic: works
            // for gnome-keyring in CI as well as KeePassXC/KWallet on a developer box).
            assertNotEquals(Provider.UNAVAILABLE, provider,
                    "A Secret Service provider is expected on the session bus");
            assertNotNull(provider.displayName);
            // detect() is just the display-name view of detectProvider().
            assertEquals(provider.displayName, ProviderDetector.detect(connection));
        } finally {
            connection.disconnect();
        }
    }
}
