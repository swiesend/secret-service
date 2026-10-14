package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.System;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A collection opened with a password is the collection it names, or none. When the password could
 * not be used, the library took the path of the newest {@code CollectionCreated} signal its service
 * had seen: an earlier collection of this client or of any other client on the bus, which then
 * received this collection's items and was deleted by its {@code delete()}.
 *
 * <p>Against {@link FakeSecretService}. Each test plants such an earlier signal, then opens a
 * collection that does not exist.</p>
 */
class CollectionCreationTest {

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
    void aPasswordOnAnotherProviderCreatesTheCollectionThroughItsPrompt() throws Exception {
        harness.start(false);
        FakeSecretService fake = harness.fake();
        try (ServiceInterface service = newService()) {
            SessionInterface session = service.openSession().orElseThrow();
            plantAnEarlierCollectionCreated(service);

            Optional<CollectionInterface> opened = session.collection("other", Optional.of("a password"));

            assertEquals(List.of("other"), fake.createCollectionCalls(),
                    "the provider cannot take the password, so it is asked to create the collection "
                            + "through its prompt");
            assertTrue(opened.isEmpty(),
                    "the user cancelled that prompt, so there is no collection to open");
        }
    }

    @Test
    void aPasswordThatGnomeKeyringDoesNotAcceptBindsNoOtherCollection() throws Exception {
        harness.start(false);
        FakeSecretService fake = harness.fake();
        // Owning org.gnome.keyring as well makes the fake gnome-keyring to the library, so it sends
        // CreateWithMasterPassword. The fake does not implement it: the call fails, as it does when
        // its reply times out.
        fake.requestBusName("org.gnome.keyring");
        try (ServiceInterface service = newService()) {
            assertTrue(service.isGnomeKeyringAvailable(), "the precondition: the library sees gnome-keyring");
            SessionInterface session = service.openSession().orElseThrow();
            plantAnEarlierCollectionCreated(service);

            Optional<CollectionInterface> opened = session.collection("other", Optional.of("a password"));

            assertTrue(opened.isEmpty(),
                    "no collection is labelled \"other\", so none may be opened under that name");
        }
    }

    /** A service created after the test has set the fake up, on the fixture's bus. */
    private ServiceInterface newService() {
        ServiceInterface service = SecretService.create(Optional.of(System.wrap(harness.clientConnection())))
                .orElseThrow(() -> new IllegalStateException("could not create the service"));
        // As in the fixture: a Completed signal missed by a descheduled client costs this timeout,
        // 120 seconds by default.
        service.setTimeout(Duration.ofSeconds(5));
        return service;
    }

    /**
     * The {@code CollectionCreated} of an earlier collection, as the service's signal handler keeps
     * it: one this client created, or one any other client on the bus did.
     */
    private static void plantAnEarlierCollectionCreated(ServiceInterface service) throws Exception {
        service.getService().getSignalHandler().handle(
                new de.swiesend.secretservice.interfaces.Service.CollectionCreated(
                        Static.ObjectPaths.SECRETS, new DBusPath(FakeSecretService.COLLECTION_PATH)));
    }
}
