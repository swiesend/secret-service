package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A provider's default collection is the one its {@code default} alias points to. The library knew
 * only gnome-keyring's ids for it, so {@code delete()} deleted KWallet's default wallet, and
 * {@code openDefault()} bound to the alias's path, so that {@code getId()} answered "default",
 * which names no collection.
 *
 * <p>Against {@link FakeSecretService}, whose collection has none of gnome-keyring's ids.</p>
 */
class DefaultCollectionTest {

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
    void theCollectionTheDefaultAliasNamesIsNotDeleted() throws Exception {
        CollectionInterface collection = harness.start(false);
        harness.fake().setDefaultAlias(FakeSecretService.COLLECTION_PATH);

        assertTrue(collection.isDefault());
        assertFalse(collection.delete(), "the provider's default collection is not deleted");
        assertEquals(0, harness.fake().collectionDeleteCalls(), "nor is its deletion requested");
    }

    @Test
    void anotherCollectionIsDeleted() throws Exception {
        // The counterpart of the test above: the refusal there is the default check's.
        CollectionInterface collection = harness.start(false);

        assertFalse(collection.isDefault());
        assertTrue(collection.delete());
        assertEquals(1, harness.fake().collectionDeleteCalls());
    }

    @Test
    void aMissingDefaultCollectionIsLogged() throws Exception {
        // ReadAlias answers "/" for no such alias, as the fake does unless a test sets one.
        harness.start(false);
        SessionInterface session = harness.service().openSession().orElseThrow();

        String log = logOf(() -> session.defaultCollection().orElseThrow().close());

        assertTrue(log.contains("The provider names no default collection"), log);
    }

    @Test
    void aDefaultCollectionIsNotLoggedAsMissing() throws Exception {
        // The counterpart of the test above.
        harness.start(false);
        harness.fake().setDefaultAlias(FakeSecretService.COLLECTION_PATH);
        SessionInterface session = harness.service().openSession().orElseThrow();

        String log = logOf(() -> session.defaultCollection().orElseThrow().close());

        assertFalse(log.contains("names no default collection"), log);
    }

    private interface Action {
        void run() throws Exception;
    }

    /** What the library logs while {@code action} runs, as slf4j-simple writes it to System.err. */
    private static String logOf(Action action) throws Exception {
        PrintStream original = java.lang.System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        java.lang.System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            action.run();
        } finally {
            java.lang.System.setErr(original);
        }
        return captured.toString(StandardCharsets.UTF_8);
    }

    @Test
    void openDefaultOpensTheCollectionTheAliasNames() throws Exception {
        harness.start(false);
        harness.fake().setDefaultAlias(FakeSecretService.COLLECTION_PATH);
        SessionInterface session = harness.service().openSession().orElseThrow();

        try (CollectionInterface collection = session.defaultCollection().orElseThrow()) {
            assertEquals(Optional.of("fake"), collection.getId(), "the id of the collection, not of the alias");
        }
    }
}
