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
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
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
    void anImplementationWithoutIsDefaultAnswersFalse() {
        // An implementation outside the library that does not declare isDefault(): every method
        // without a body throws, so only the interface's default body can answer.
        CollectionInterface other = (CollectionInterface) Proxy.newProxyInstance(
                CollectionInterface.class.getClassLoader(), new Class<?>[]{CollectionInterface.class},
                (proxy, method, args) -> {
                    if (method.isDefault()) return InvocationHandler.invokeDefault(proxy, method, args);
                    throw new UnsupportedOperationException(method.getName());
                });

        assertFalse(other.isDefault());
        assertFalse(other.allowDeletingTheDefault(), "the setting is not taken");
        assertFalse(other.refuseDeletingTheDefault(), "the setting is not taken");
    }

    @Test
    void aCollectionIsNotDeletedWhileTheDefaultAliasCannotBeRead() throws Exception {
        // It may be the provider's default collection then.
        CollectionInterface collection = harness.start(false);
        harness.fake().setRefuseReadAlias(true);

        assertFalse(collection.delete());
        assertEquals(0, harness.fake().collectionDeleteCalls());
    }

    @Test
    void aCollectionIsNotDeletedOnAnInterruptedThread() throws Exception {
        // On an interrupted thread, dbus-java gives up on the reply to ReadAlias at once.
        CollectionInterface collection = harness.start(false);
        try {
            Thread.currentThread().interrupt();
            assertFalse(collection.delete());
        } finally {
            Thread.interrupted();
        }
        // A Delete would reach the fake although the call gave up on its reply: give it the time.
        Thread.sleep(500);
        assertEquals(0, harness.fake().collectionDeleteCalls());
    }

    @Test
    void theCollectionThatOpenDefaultOpenedIsNotDeletedWhenTheAliasCannotBeReadAnyMore() throws Exception {
        harness.start(false);
        harness.fake().setDefaultAlias(FakeSecretService.COLLECTION_PATH);
        SessionInterface session = harness.service().openSession().orElseThrow();

        try (CollectionInterface collection = session.defaultCollection().orElseThrow()) {
            harness.fake().setRefuseReadAlias(true);

            assertTrue(collection.isDefault(), "openDefault() opened it");
            assertFalse(collection.delete());
            assertEquals(0, harness.fake().collectionDeleteCalls());
        }
    }

    @Test
    void theDefaultCollectionIsDeletedOnceThatIsAllowed() throws Exception {
        harness.start(false);
        harness.fake().setDefaultAlias(FakeSecretService.COLLECTION_PATH);
        SessionInterface session = harness.service().openSession().orElseThrow();

        try (CollectionInterface collection = session.defaultCollection().orElseThrow()) {
            assertTrue(collection.allowDeletingTheDefault());

            assertTrue(collection.delete());
            assertEquals(1, harness.fake().collectionDeleteCalls());
        }
    }

    @Test
    void theDefaultCollectionIsRefusedAgainAfterItWasAllowed() throws Exception {
        CollectionInterface collection = harness.start(false);
        harness.fake().setDefaultAlias(FakeSecretService.COLLECTION_PATH);
        collection.allowDeletingTheDefault();

        assertTrue(collection.refuseDeletingTheDefault());
        assertFalse(collection.delete());
        assertEquals(0, harness.fake().collectionDeleteCalls());
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
