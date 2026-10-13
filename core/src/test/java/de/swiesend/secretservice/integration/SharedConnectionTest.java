package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.functional.System;
import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import org.freedesktop.dbus.interfaces.DBus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every {@code System.connect()} in the JVM gets dbus-java's shared connection, which counts its
 * holders and disconnects when the last one closes it. Closing one System twice gave up a second
 * share, another holder's: {@code SecretService.close()} closes the system it was given, and a
 * try-with-resources over both closed it again.
 *
 * <p>On the fixture's private bus, connected through the {@code DBUS_SESSION_BUS_ADDRESS} system
 * property, so that this test's two Systems are the connection's only holders.</p>
 */
class SharedConnectionTest {

    private static final String ADDRESS = "DBUS_SESSION_BUS_ADDRESS";

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private String saved;

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
        saved = java.lang.System.getProperty(ADDRESS);
    }

    @AfterEach
    void stop() {
        if (saved == null) {
            java.lang.System.clearProperty(ADDRESS);
        } else {
            java.lang.System.setProperty(ADDRESS, saved);
        }
        harness.stop();
    }

    @Test
    void closingASystemTwiceLeavesTheOtherHolderConnected() throws Exception {
        java.lang.System.setProperty(ADDRESS, harness.startBus());
        SystemInterface first = System.connect().orElseThrow();
        SystemInterface second = System.connect().orElseThrow();
        try {
            first.close();
            first.close();

            DBus bus = second.getConnection().getRemoteObject("org.freedesktop.DBus", "/org/freedesktop/DBus", DBus.class);
            assertTrue(Arrays.asList(bus.ListNames()).contains("org.freedesktop.DBus"),
                    "the other holder's connection still works");
        } finally {
            second.close();
        }
    }
}
