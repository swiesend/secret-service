package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Failure;
import de.swiesend.secretservice.Failure.Reason;
import de.swiesend.secretservice.Result;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Why no service was created: no session bus, nothing on it that provides the Secret Service, or
 * a provider that opens no encrypted session. A caller that falls back to another store, as in a
 * container, tells these apart from a provider that answered.
 *
 * <p>dbus-java takes the session bus's address from the system property
 * {@code DBUS_SESSION_BUS_ADDRESS} before the environment, so these tests set it, and put it back
 * afterwards.</p>
 */
class ServiceCreationTest {

    private static final String ADDRESS = "DBUS_SESSION_BUS_ADDRESS";

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private String savedAddress;

    @BeforeEach
    void saveAddress() {
        savedAddress = System.getProperty(ADDRESS);
    }

    @AfterEach
    void stop() {
        if (savedAddress == null) System.clearProperty(ADDRESS);
        else System.setProperty(ADDRESS, savedAddress);
        harness.stop();
    }

    private static void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(), "dbus-daemon is not on the PATH");
    }

    private static Result<ServiceInterface> createOn(org.freedesktop.dbus.connections.impl.DBusConnection connection) {
        return SecretService.createChecked(
                Optional.of(de.swiesend.secretservice.functional.System.wrap(connection)));
    }

    @Test
    void aSessionBusThatCannotBeReachedIsNoProvider() {
        System.setProperty(ADDRESS, "unix:path=/nonexistent/secret-service-test/bus");

        Result<ServiceInterface> created = SecretService.createChecked();

        assertEquals(Optional.of(Reason.NO_PROVIDER), created.reason());
        assertNotNull(created.failure().orElseThrow().cause(), "the exception of dbus-java stays with the failure");
    }

    @Test
    void aMalformedSessionBusAddressIsNoProviderAndThrowsNothing() {
        System.setProperty(ADDRESS, "nonsense");

        assertEquals(Optional.of(Reason.NO_PROVIDER), SecretService.createChecked().reason());
        assertEquals(Optional.empty(), SecretService.create(), "an empty answer, not dbus-java's exception");
    }

    @Test
    void aBusWithoutAProviderIsNoProvider() throws Exception {
        requireDbus();
        harness.startBus();

        assertEquals(Optional.of(Reason.NO_PROVIDER), createOn(harness.connectAnother()).reason());
    }

    @Test
    void aProviderThatOpensNoEncryptedSessionSaysWhy() throws Exception {
        requireDbus();
        harness.start(false);
        harness.fake().setRefuseEncryptedSessions(true);

        Failure failure = createOn(harness.connectAnother()).failure().orElseThrow();

        assertEquals(Reason.OTHER, failure.reason());
        assertTrue(failure.errorName().endsWith("NotSupported"), "the provider's error: " + failure.errorName());
    }

    @Test
    void aProviderOnTheSessionBusMakesAService() throws Exception {
        requireDbus();
        harness.start(false);
        System.setProperty(ADDRESS, harness.address());

        Result<ServiceInterface> created = SecretService.createChecked();
        try {
            assertTrue(created.isOk(), created.toString());
        } finally {
            if (created.isOk()) created.value().orElseThrow().close();
        }
    }
}
