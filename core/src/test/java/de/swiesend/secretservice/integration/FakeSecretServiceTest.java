package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Collection;
import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Item;
import de.swiesend.secretservice.Pair;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.Session;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.TransportEncryption;
import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import de.swiesend.secretservice.handlers.MessageHandler;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The fake is only as good as its fidelity, so each of its methods is driven here through the
 * library's own low-level API, the way the library itself calls it. A test that passes against a
 * fake that silently misbehaves proves nothing about the library.
 */
class FakeSecretServiceTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private FakeSecretService fake;
    private Service service;
    private TransportEncryption.EncryptedSession encrypted;
    private DBusPath session;

    @BeforeEach
    void start() throws Exception {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
        harness.start(false);
        fake = harness.fake();
        service = harness.rawService();
        encrypted = harness.session().getEncryptedSession();
        session = harness.session().getSession().getPath();
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    @Test
    void aPlainSessionCarriesTheSecretUnencryptedUntilItIsClosed() {
        Pair<Variant<byte[]>, DBusPath> plain = service.openSession(Static.Algorithm.PLAIN, new Variant<>(""))
                .orElseThrow();
        Item item = new Item(new DBusPath(FakeSecretService.ITEM_PATH), service);

        Secret secret = item.getSecret(plain.b).orElseThrow();
        assertArrayEquals(FakeSecretService.SECRET_VALUE.getBytes(StandardCharsets.UTF_8), secret.getSecretValue());

        assertTrue(new Session(plain.b, service).close());
        MessageHandler.Reply afterClose = service.getMessageHandler().sendChecked(Static.Service.SECRETS,
                FakeSecretService.ITEM_PATH, Static.Interfaces.ITEM, "GetSecret", "o", plain.b);
        assertEquals("org.freedesktop.Secret.Error.NoSession", afterClose.errorName(),
                "a closed session is gone, and the error says so by its specified name");
    }

    @Test
    void anItemIsCreatedReadChangedSearchedAndDeleted() {
        Collection collection = new Collection(new DBusPath(FakeSecretService.COLLECTION_PATH), service.getConnection());
        Map<String, String> attributes = Map.of("app", "fake-test");
        Pair<DBusPath, DBusPath> created = collection.createItem(
                Item.createProperties("created", attributes), encrypted.encrypt("first").orElseThrow(), false)
                .orElseThrow();
        assertEquals("/", created.b.getPath(), "creating an item needs no prompt");
        String path = created.a.getPath();
        Item item = new Item(created.a, service);

        assertEquals("first", read(item));
        assertTrue(item.setSecret(encrypted.encrypt("second").orElseThrow()));
        assertEquals("second", read(item));
        assertEquals(Optional.of("second"), fake.secretOf(path));

        assertTrue(item.setLabel("renamed"));
        assertEquals(Optional.of("renamed"), item.getLabel());
        assertTrue(item.setAttributes(Map.of("app", "fake-test", "kind", "changed")));
        assertEquals(Optional.of(Map.of("app", "fake-test", "kind", "changed")), item.getAttributes());
        assertEquals(Optional.of("org.freedesktop.Secret.Generic"), item.getType());
        assertTrue(item.created().isPresent() && item.modified().isPresent());

        assertTrue(paths(service.searchItems(attributes).orElseThrow().a).contains(path),
                "the service finds the item by a subset of its attributes");
        assertEquals(List.of(path), paths(collection.searchItems(Map.of("kind", "changed")).orElseThrow()));
        assertEquals(List.of(), paths(collection.searchItems(Map.of("kind", "other")).orElseThrow()));

        Pair<DBusPath, DBusPath> replaced = collection.createItem(
                Item.createProperties("replaced", Map.of("app", "fake-test", "kind", "changed")),
                encrypted.encrypt("third").orElseThrow(), true)
                .orElseThrow();
        assertEquals(path, replaced.a.getPath(), "replace=true overwrites the item with the same attributes");
        assertEquals("third", read(item));

        Map<DBusPath, Secret> secrets = service.getSecrets(
                List.of(created.a, new DBusPath(FakeSecretService.ITEM_PATH)), session).orElseThrow();
        assertEquals(List.of(path, FakeSecretService.ITEM_PATH), paths(List.copyOf(secrets.keySet())));

        assertEquals(Optional.of("/"), item.delete().map(DBusPath::getPath), "deleting needs no prompt by default");
        assertFalse(fake.hasItem(path));
        assertFalse(paths(collection.getItems().orElseThrow()).contains(path));
    }

    @Test
    void aCollectionIsCreatedThroughAPromptAliasedAndDeleted() {
        Pair<DBusPath, DBusPath> created = service.createCollection(Collection.createProperties("made")).orElseThrow();
        assertEquals("/", created.a.getPath(), "the collection exists only once the user approves");
        Prompt.Completed completed = await(created.b);
        assertNotNull(completed, "the prompt completes once the client shows it");
        assertFalse(completed.dismissed);
        DBusPath made = new DBusPath(completed.result.getValue().toString());
        assertEquals(List.of(created.b.getPath()), fake.promptCalls());
        assertTrue(paths(service.getCollections().orElseThrow()).contains(made.getPath()));
        assertEquals(Optional.of("made"), new Collection(made, service.getConnection()).getLabel());

        assertTrue(service.setAlias("extra", made));
        assertEquals(Optional.of(made.getPath()), service.readAlias("extra").map(DBusPath::getPath));
        Collection byAlias = new Collection(new DBusPath(Static.ObjectPaths.ALIASES + "/extra"), service.getConnection());
        assertEquals(Optional.of("made"), byAlias.getLabel(), "the alias path serves the same collection");
        assertTrue(service.setAlias("extra", new DBusPath("/")));
        assertEquals(Optional.of("/"), service.readAlias("extra").map(DBusPath::getPath));

        assertEquals(Optional.of("/"), new Collection(made, service.getConnection()).delete().map(DBusPath::getPath));
        assertFalse(paths(service.getCollections().orElseThrow()).contains(made.getPath()));
    }

    @Test
    void aDismissedPromptChangesNothing() {
        fake.setDismissPrompts(true);
        List<String> before = paths(service.getCollections().orElseThrow());

        Pair<DBusPath, DBusPath> created = service.createCollection(Collection.createProperties("refused")).orElseThrow();
        Prompt.Completed completed = await(created.b);

        assertNotNull(completed);
        assertTrue(completed.dismissed);
        assertEquals(before, paths(service.getCollections().orElseThrow()));
    }

    @Test
    void aLockedCollectionRefusesItsSecretsByTheSpecifiedError() {
        DBusPath collection = new DBusPath(FakeSecretService.COLLECTION_PATH);
        Item item = new Item(new DBusPath(FakeSecretService.ITEM_PATH), service);

        List<String> collectionOnly = List.of(FakeSecretService.COLLECTION_PATH);
        assertEquals(collectionOnly, paths(service.lock(List.of(collection)).orElseThrow().a));
        assertTrue(item.isLocked(), "an item reports locked while its collection is");
        MessageHandler.Reply refused = service.getMessageHandler().sendChecked(Static.Service.SECRETS,
                FakeSecretService.ITEM_PATH, Static.Interfaces.ITEM, "GetSecret", "o", session);
        assertEquals(MessageHandler.Outcome.DENIED, refused.outcome());
        assertEquals("org.freedesktop.Secret.Error.IsLocked", refused.errorName());

        assertEquals(collectionOnly, paths(service.unlock(List.of(collection)).orElseThrow().a));
        assertFalse(item.isLocked());

        assertTrue(service.lockService());
        assertTrue(item.isLocked(), "LockService locks every collection");
        service.unlock(List.of(collection));

        DBusPath change = service.changeLock(collection).orElseThrow();
        Prompt.Completed completed = await(change);
        assertNotNull(completed);
        assertFalse(completed.dismissed);
    }

    @Test
    void theGnomeKeyringExtensionChecksTheMasterPassword() {
        InternalUnsupportedGuiltRiddenInterface gnome = new InternalUnsupportedGuiltRiddenInterface(service);
        DBusPath path = gnome.createWithMasterPassword(Collection.createProperties("gnome"),
                encrypted.encrypt("password").orElseThrow()).orElseThrow();

        service.lock(List.of(path));
        assertFalse(gnome.unlockWithMasterPassword(path, encrypted.encrypt("wrong").orElseThrow()));
        assertTrue(new Collection(path, service.getConnection()).isLocked());
        assertTrue(gnome.unlockWithMasterPassword(path, encrypted.encrypt("password").orElseThrow()));
        assertFalse(new Collection(path, service.getConnection()).isLocked());

        assertTrue(gnome.changeWithMasterPassword(path, encrypted.encrypt("password").orElseThrow(),
                encrypted.encrypt("changed").orElseThrow()));
        service.lock(List.of(path));
        assertTrue(gnome.unlockWithMasterPassword(path, encrypted.encrypt("changed").orElseThrow()));

        assertNotEquals(Optional.of("/"), gnome.changeWithPrompt(path).map(DBusPath::getPath),
                "changing the password through the dialog is a prompt");
    }

    @Test
    void signalsArriveAsTheLibrarysOwnClasses() {
        // The regression this guards: wire interfaces annotated with the D-Bus names made
        // dbus-java build every later Secret Service signal as a class of this fake, which the
        // library's SignalHandler does not match. CollectionCreated is the signal the functional
        // API waits for after it creates a collection.
        DBusPath path = new InternalUnsupportedGuiltRiddenInterface(service)
                .createWithMasterPassword(Collection.createProperties("signalled"),
                        encrypted.encrypt("password").orElseThrow())
                .orElseThrow();
        fake.awaitSignals();
        de.swiesend.secretservice.interfaces.Service.CollectionCreated signal = null;
        for (int i = 0; i < 50 && signal == null; i++) {
            signal = service.getSignalHandler().getLastHandledSignal(
                    de.swiesend.secretservice.interfaces.Service.CollectionCreated.class, Static.ObjectPaths.SECRETS);
            if (signal == null) sleep();
        }
        assertNotNull(signal, "the client received CollectionCreated as the library's own class");
        assertEquals(path.getPath(), signal.collection.getPath());
    }

    /** Shows the prompt and waits for its answer: seconds at most, not the default two minutes. */
    private Prompt.Completed await(DBusPath prompt) {
        return new Prompt(service).await(prompt, Duration.ofSeconds(5));
    }

    private String read(Item item) {
        Secret secret = item.getSecret(session).orElseThrow();
        return new String(encrypted.decrypt(secret).orElseThrow());
    }

    private static List<String> paths(List<DBusPath> paths) {
        return paths.stream().map(DBusPath::getPath).collect(Collectors.toList());
    }

    private static void sleep() {
        try {
            Thread.sleep(Static.DBus.DEFAULT_DELAY_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
