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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code createDefaultCollection} opens the provider's default collection, and creates one under
 * the alias {@code default} only where the provider names none: never another collection in its
 * place. Against {@link FakeSecretService}, which creates a collection behind a dialog that it
 * completes when the client shows it.
 */
class CreateDefaultCollectionTest {

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

    private static Optional<String> labelOf(Result<CollectionInterface> collection) {
        return collection.value().orElseThrow(() -> new AssertionError(collection.toString())).getLabel();
    }

    @Test
    void aMissingDefaultCollectionIsCreatedWithTheLabel() throws Exception {
        harness.start(false);
        removeTheDefaultAlias();

        assertEquals(Optional.of("Login"), labelOf(harness.session().createDefaultCollection("Login")));
        assertEquals(Optional.of("Login"), labelOf(harness.session().defaultCollectionChecked()),
                "the provider's default now");
    }

    @Test
    void anExistingDefaultCollectionIsOpenedAndNothingIsCreated() throws Exception {
        harness.start(false);

        assertEquals(Optional.of(FakeSecretService.COLLECTION_LABEL),
                labelOf(harness.session().createDefaultCollection("Login")));
        assertTrue(harness.fake().calls().stream().noneMatch(call -> call.startsWith("Service.CreateCollection")));
    }

    @Test
    void anotherCollectionDoesNotStandInForTheDefault() throws Exception {
        harness.start(false);
        // As gnome-keyring's in-memory collection "session" would.
        harness.session().collection("session", Optional.empty()).orElseThrow();
        removeTheDefaultAlias();

        assertEquals(Optional.of("Login"), labelOf(harness.session().createDefaultCollection("Login")));
    }

    @Test
    void aDismissedDialogCreatesNothing() throws Exception {
        harness.start(false);
        removeTheDefaultAlias();
        harness.fake().setDismissPrompts(true);

        assertEquals(Optional.of(Reason.DISMISSED), harness.session().createDefaultCollection("Login").reason());
        assertEquals(Optional.of(Reason.NO_DEFAULT_COLLECTION), harness.session().defaultCollectionChecked().reason());
    }

    @Test
    void aBlankLabelIsRefused() throws Exception {
        harness.start(false);

        assertThrows(IllegalArgumentException.class, () -> harness.session().createDefaultCollection(" "));
        assertThrows(IllegalArgumentException.class, () -> harness.session().createDefaultCollection(null));
    }
}
