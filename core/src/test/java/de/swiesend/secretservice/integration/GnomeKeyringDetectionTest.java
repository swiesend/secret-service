package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.System;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * gnome-keyring's own interface is reached through the provider that serves
 * {@code org.freedesktop.secrets}, so the library may use it only when that provider is
 * gnome-keyring. The {@code org.gnome.keyring} name alone does not say so: it is activatable
 * wherever gnome-keyring is installed, and taken when gnome-keyring runs next to another provider.
 */
class GnomeKeyringDetectionTest {

    private static final String GNOME_KEYRING = "org.gnome.keyring";

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
    void gnomeKeyringNextToAnotherProviderIsNotUsed() throws Exception {
        harness.start(false);
        // gnome-keyring runs, but the fake serves the secrets: the desktop of a KeePassXC user.
        harness.connectAnother().requestBusName(GNOME_KEYRING);
        try (ServiceInterface service = newService()) {
            assertFalse(service.isGnomeKeyringAvailable(),
                    "org.gnome.keyring belongs to another connection than org.freedesktop.secrets");
        }
    }

    @Test
    void gnomeKeyringServingTheSecretsIsUsed() throws Exception {
        harness.start(false);
        harness.fake().requestBusName(GNOME_KEYRING);
        try (ServiceInterface service = newService()) {
            assertTrue(service.isGnomeKeyringAvailable(),
                    "the connection that serves org.freedesktop.secrets also owns org.gnome.keyring");
        }
    }

    /** A service created after the test has set the bus up, on the fixture's bus. */
    private ServiceInterface newService() {
        return SecretService.create(Optional.of(System.wrap(harness.clientConnection())))
                .orElseThrow(() -> new IllegalStateException("could not create the service"));
    }
}
