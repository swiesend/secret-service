package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Failure.Reason;
import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Result;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A provider that names no default collection, as on an account where nothing has created the login
 * keyring yet, is told apart from one that does. Against {@link FakeSecretService}, whose alias
 * {@code default} names its collection until a test removes it.
 */
class MissingDefaultCollectionTest {

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

    private void removeTheDefaultAlias() {
        assertTrue(harness.rawService().setAlias("default", new DBusPath("/")));
    }

    @Test
    void theDefaultCollectionOpensWhenTheProviderNamesOne() throws Exception {
        harness.start(false);

        Result<CollectionInterface> opened = harness.session().defaultCollectionChecked();

        assertTrue(opened.isOk(), opened.toString());
        assertEquals(Optional.of(FakeSecretService.COLLECTION_LABEL), opened.value().orElseThrow().getLabel());
    }

    @Test
    void aProviderThatNamesNoDefaultCollectionSaysSo() throws Exception {
        harness.start(false);
        removeTheDefaultAlias();

        assertEquals(Optional.of(Reason.NO_DEFAULT_COLLECTION), harness.session().defaultCollectionChecked().reason());
        assertTrue(harness.session().defaultCollection().isPresent(),
                "defaultCollection() answers as before: the collection at the alias's path");
    }

    @Test
    void aProviderOffTheBusIsNoProvider() throws Exception {
        harness.start(false);
        harness.releaseProviderName();

        assertEquals(Optional.of(Reason.NO_PROVIDER), harness.session().defaultCollectionChecked().reason());
    }
}
