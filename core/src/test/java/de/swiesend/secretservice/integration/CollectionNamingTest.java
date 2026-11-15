package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A collection object is bound to a path that comes from outside: the result of the prompt that
 * creates a collection, or an id of the caller's. The library took both as they came. A prompt
 * that completed with an empty result gave a collection at the path {@code ""}, one with
 * {@code "/"} threw out of {@code collection()}, and an id with a {@code /} in it bound the
 * collection to an item's path, or to any other object of the provider.
 *
 * <p>Against {@link FakeSecretService}, whose prompt completes with what a test gives it.</p>
 */
class CollectionNamingTest {

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

    /** What {@code collection()} gives for a new label when the creating prompt completes with {@code result}. */
    private Optional<CollectionInterface> createdWith(SessionInterface session, Variant<?> result) {
        FakeSecretService fake = harness.fake();
        int calls = fake.createCollectionCalls().size();
        fake.setCreateCollectionResult(result);

        Optional<CollectionInterface> created = session.collection("a new one", Optional.empty());
        assertEquals(calls + 1, fake.createCollectionCalls().size(), "the provider was asked to create it");
        return created;
    }

    @Test
    void aPromptResultThatNamesNoCollectionGivesNone() throws Exception {
        harness.start(false);
        SessionInterface session = harness.service().openSession().orElseThrow();

        assertEquals(Optional.empty(), createdWith(session, new Variant<>("")), "an empty result");
        assertEquals(Optional.empty(), createdWith(session, new Variant<>(new DBusPath("/"))), "the path for none");
        assertEquals(Optional.empty(), createdWith(session, new Variant<>(new ArrayList<DBusPath>(), "ao")),
                "the result of another operation");
        assertEquals(Optional.empty(), createdWith(session, new Variant<>("fake/1")), "no object path");
        assertEquals(Optional.empty(), createdWith(session, new Variant<>(FakeSecretService.COLLECTION_PATH + "/")));
        assertEquals(Optional.empty(), createdWith(session, new Variant<>(42)));
    }

    @Test
    void aPromptResultThatNamesACollectionGivesIt() throws Exception {
        harness.start(false);
        SessionInterface session = harness.service().openSession().orElseThrow();

        CollectionInterface created = createdWith(session,
                new Variant<>(new DBusPath(FakeSecretService.COLLECTION_PATH))).orElseThrow();

        assertEquals(Optional.of("fake"), created.getId(), "the collection at that path");
    }

    @Test
    void anIdThatIsNoPathElementOpensNoCollection() throws Exception {
        harness.start(false);
        SessionInterface session = harness.service().openSession().orElseThrow();

        for (String id : List.of("fake/1", "fake/", "/fake", "../fake", "fa ke", "fake\nINFO forged", "f-ake", "fäke")) {
            assertEquals(Optional.empty(), session.collectionById(id), id);
        }
        assertTrue(session.getCollections().isEmpty(), "and the session keeps none of them");
    }

    @Test
    void anIdOpensItsCollection() throws Exception {
        harness.start(false);
        SessionInterface session = harness.service().openSession().orElseThrow();

        CollectionInterface collection = session.collectionById("fake").orElseThrow();

        assertEquals(Optional.of("fake"), collection.getId());
        assertEquals(Optional.of(FakeSecretService.COLLECTION_LABEL), collection.getLabel());
    }
}
