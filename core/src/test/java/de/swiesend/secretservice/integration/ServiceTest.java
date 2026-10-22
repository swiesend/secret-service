package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.*;
import de.swiesend.secretservice.Collection;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.errors.NoSuchObject;
import de.swiesend.secretservice.integration.test.Context;
import de.swiesend.secretservice.integration.test.Dialogs;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static de.swiesend.secretservice.Static.Convert.toStrings;
import static org.junit.jupiter.api.Assertions.*;


public class ServiceTest {

    private Logger log = LoggerFactory.getLogger(getClass());
    private Context context;

    @BeforeEach
    public void beforeEach(TestInfo info) {
        log.info(info.getDisplayName());
        context = new Context(log);
    }

    @AfterEach
    public void afterEach() {
        context.after();
    }

    @Test
    public void openSession() {
        context.ensureService();

        Optional<Pair<Variant<byte[]>, DBusPath>> response = context.service.openSession(Static.Algorithm.PLAIN, new Variant<>(""));
        log.info(response.toString());

        assertEquals("s", response.get().a.getSig());
        assertEquals("", response.get().a.getValue(), "the value of an empty byte[] behaves odd as it returns a String.");

        DBusPath sessionPath = response.get().b;
        assertTrue(sessionPath.getPath().startsWith("/org/freedesktop/secrets/session/s"));
    }

    @Test
    public void openSessionWithTransportEncryption() {
        context.ensureService();

        byte[] input = new byte[]{
                (byte) 0x7e, (byte) 0x71, (byte) 0x32, (byte) 0xe5, (byte) 0x66, (byte) 0xc4, (byte) 0x4b, (byte) 0xb8,
                (byte) 0xf3, (byte) 0x13, (byte) 0xc3, (byte) 0x06, (byte) 0x31, (byte) 0xcf, (byte) 0xd3, (byte) 0xa0,
                (byte) 0xa4, (byte) 0xf7, (byte) 0x3a, (byte) 0xbd, (byte) 0xd0, (byte) 0xa8, (byte) 0x11, (byte) 0xbe,
                (byte) 0xf0, (byte) 0x04, (byte) 0xaa, (byte) 0x70, (byte) 0x7d, (byte) 0x62, (byte) 0x6a, (byte) 0x7e,
                (byte) 0xd5, (byte) 0x0b, (byte) 0x2d, (byte) 0x75, (byte) 0x7e, (byte) 0x97, (byte) 0xb8, (byte) 0x22,
                (byte) 0xa7, (byte) 0x1d, (byte) 0xea, (byte) 0x8a, (byte) 0xf7, (byte) 0x54, (byte) 0x1e, (byte) 0x38,
                (byte) 0xdc, (byte) 0xab, (byte) 0x1a, (byte) 0x51, (byte) 0x18, (byte) 0x88, (byte) 0x7c, (byte) 0x43,
                (byte) 0xe0, (byte) 0x55, (byte) 0x52, (byte) 0xa2, (byte) 0xdf, (byte) 0xae, (byte) 0x78, (byte) 0x40,
                (byte) 0x3d, (byte) 0xd8, (byte) 0xd7, (byte) 0x2e, (byte) 0x2d, (byte) 0xeb, (byte) 0x0d, (byte) 0xa7,
                (byte) 0x67, (byte) 0x9f, (byte) 0x18, (byte) 0x1d, (byte) 0x7e, (byte) 0xd2, (byte) 0x2a, (byte) 0x84,
                (byte) 0xff, (byte) 0xd6, (byte) 0xb5, (byte) 0x0d, (byte) 0x97, (byte) 0xc4, (byte) 0x84, (byte) 0x8f,
                (byte) 0x67, (byte) 0x71, (byte) 0x01, (byte) 0xc5, (byte) 0xaf, (byte) 0x2f, (byte) 0x0c, (byte) 0xe2,
                (byte) 0x15, (byte) 0x91, (byte) 0x39, (byte) 0x5d, (byte) 0x38, (byte) 0xc9, (byte) 0x23, (byte) 0x8f,
                (byte) 0x80, (byte) 0x96, (byte) 0x0e, (byte) 0x6b, (byte) 0xcd, (byte) 0x2f, (byte) 0xb0, (byte) 0x2c,
                (byte) 0x56, (byte) 0x95, (byte) 0x41, (byte) 0xdf, (byte) 0x3b, (byte) 0x35, (byte) 0x2a, (byte) 0xa0,
                (byte) 0x67, (byte) 0xf2, (byte) 0x14, (byte) 0xe3, (byte) 0x7c, (byte) 0x47, (byte) 0x5e, (byte) 0xbf
        };
        assertEquals(128, input.length);

        Optional<Pair<Variant<byte[]>, DBusPath>> response = context.service.openSession(
                Static.Algorithm.DH_IETF1024_SHA256_AES128_CBC_PKCS7, new Variant<>(input));
        log.info(response.toString());

        // As declared: the value is a byte[], whatever dbus-java decoded the "ay" into.
        byte[] peerPublicKey = response.get().a.getValue();
        // The peer's DH public value is an unsigned big-endian integer of up to 1024 bits, sent
        // without leading zero bytes: about one value in 256 has a zero top byte and arrives as
        // 127 bytes, and rarer ones as fewer.
        assertTrue(peerPublicKey.length > 0 && peerPublicKey.length <= 128,
                "the peer public key must be 1 to 128 bytes, was " + peerPublicKey.length);

        DBusPath sessionPath = response.get().b;
        assertTrue(sessionPath.getPath().startsWith(Static.ObjectPaths.SESSION + "/s"));
    }

    @Test
    @EnabledIfSystemProperty(named = Dialogs.ANSWERED, matches = "true",
            disabledReason = "Creates a collection without a password, which gnome-keyring does only through its dialog")
    public void createCollection() {
        context.ensureCollection();

        DBusPath deletePrompt = context.collection.delete().orElse(new DBusPath("/"));
        if (!deletePrompt.getPath().equals("/")) {
            context.prompt.await(deletePrompt);
        }

        List<DBusPath> before = context.service.getCollections().orElse(new ArrayList<>());

        Map<String, Variant> properties = Collection.createProperties("test");
        boolean created = create(properties);
        if (!created) {
            // gnome-keyring dismisses about one create in 256 after its dialog was answered, as it
            // cannot decrypt the password from its prompter. Someone answers every dialog here, so
            // a dismissed create is that bug, and the test fails on it only when the second create
            // meets it too, once in 65536 runs.
            log.warn("{}: creating the collection once more",
                    ProviderBug.GNOME_KEYRING_DISMISSES_AN_ANSWERED_CREATE_PROMPT);
            created = create(properties);
        }
        assertTrue(created, "the dialog was answered");

        List<DBusPath> after = context.service.getCollections().get();
        assertEquals(before.size() + 1, after.size());
    }

    /**
     * Creates the collection, through gnome-keyring's dialog where the provider gives a prompt.
     *
     * @return whether the collection was created; false when its prompt was dismissed
     */
    private boolean create(Map<String, Variant> properties) {
        Pair<DBusPath, DBusPath> response = context.service.createCollection(properties).get();
        log.info(response.toString());

        DBusPath collectionPath = response.a;
        DBusPath createPrompt = response.b;
        if (!collectionPath.getPath().equals("/")) {
            assertEquals("/", createPrompt.getPath());
            return true;
        }
        assertTrue(createPrompt.getPath().startsWith("/org/freedesktop/secrets/prompt/p"));
        Prompt.Completed completed = context.prompt.await(createPrompt);
        assertNotNull(completed, "the prompt completed");
        return !completed.dismissed;
    }

    @Test
    public void searchItems() {
        context.ensureItem();

        Map<String, String> attributes = new HashMap<>();
        attributes.put("Attribute1", "Value1");

        Pair<List<DBusPath>, List<DBusPath>> response = context.service.searchItems(attributes).get();
        List<String> unlocked = toStrings(response.a);
        List<String> locked = toStrings(response.b);

        assertTrue(unlocked.size() >= 0);
        assertTrue(unlocked.get(0).startsWith("/org/freedesktop/secrets/collection/test/"));
        assertTrue(locked.isEmpty());
    }

    @Test
    @EnabledIfSystemProperty(named = Dialogs.ANSWERED, matches = "true",
            disabledReason = "Unlocks through gnome-keyring's password dialog, which needs a user")
    public void unlockCollections() {

        Pair<List<DBusPath>, DBusPath> response;
        List<DBusPath> locked;
        List<DBusPath> unlocked;
        DBusPath prompt;
        Prompt.Completed completed;

        // unlock a collection
        context.ensureCollection();

        ArrayList<DBusPath> lockables = new ArrayList<>();
        lockables.add(context.collection.getPath());

        response = context.service.lock(lockables).get();
        log.info(response.toString());
        locked = response.a;
        assertEquals(1, locked.size());
        prompt = response.b;
        assertEquals("/", prompt.getPath());

        response = context.service.unlock(lockables).get();
        log.info(response.toString());
        unlocked = response.a;
        assertEquals(0, unlocked.size());
        prompt = response.b;
        completed = context.prompt.await(prompt);
        assertNotNull(completed, "the prompt completed");
        assertFalse(completed.dismissed, "the dialog was answered");
        assertFalse(context.collection.isLocked());
    }

    @Test
    @EnabledIfSystemProperty(named = Dialogs.ANSWERED, matches = "true",
            disabledReason = "Unlocks through gnome-keyring's password dialog, which needs a user")
    public void unlockItems() {
        context.ensureItem();

        Pair<List<DBusPath>, DBusPath> response;
        List<DBusPath> locked, unlocked;
        DBusPath prompt;

        List<DBusPath> items = context.collection.getItems().get();

        response = context.service.lock(items).get();
        log.info(response.toString());
        locked = response.a;
        assertEquals(1, locked.size());
        prompt = response.b;
        assertEquals("/", prompt.getPath());

        response = context.service.unlock(items).get();
        log.info(response.toString());
        unlocked = response.a;
        assertEquals(0, unlocked.size());
        prompt = response.b;
        Prompt.Completed completed = context.prompt.await(prompt);
        assertNotNull(completed, "the prompt completed");
        assertFalse(completed.dismissed, "the dialog was answered");
        assertFalse(context.item.isLocked());
    }

    @Test
    @EnabledIfSystemProperty(named = Dialogs.ANSWERED, matches = "true",
            disabledReason = "Locks the user's login keyring, which only its password dialog unlocks again")
    @EnabledIfSystemProperty(named = Dialogs.DEFAULT_COLLECTION, matches = "throwaway",
            disabledReason = Dialogs.NOT_A_THROWAWAY_KEYRING)
    public void lockCommonCollections() throws InterruptedException, NoSuchObject {
        context.ensureSession();

        // lock common collections:
        //   * alias/default == collection/login (if not assigned otherwise)
        //   * collection/login
        //   * collection/session
        ArrayList<DBusPath> collections = new ArrayList<>();
        collections.add(Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION));
        collections.add(Static.Convert.toObjectPath(Static.ObjectPaths.LOGIN_COLLECTION));
        collections.add(Static.Convert.toObjectPath(Static.ObjectPaths.SESSION_COLLECTION));

        Pair<List<DBusPath>, DBusPath> response = context.service.lock(collections).get();
        log.info(response.toString());

        List<DBusPath> locked = response.a;
        assertEquals(Static.ObjectPaths.DEFAULT_COLLECTION, locked.get(0).getPath());
        assertEquals(Static.ObjectPaths.LOGIN_COLLECTION, locked.get(1).getPath());
        assertEquals(Static.ObjectPaths.SESSION_COLLECTION, locked.get(2).getPath());

        DBusPath prompt = response.b;
        assertEquals("/", prompt.getPath());

        for (int i = 0; i < collections.size(); i++) {
            List<DBusPath> collection = Arrays.asList(new DBusPath[]{collections.get(i)});
            response = context.service.unlock(collection).get();
            prompt = response.b;
            if (!prompt.getPath().equals("/")) {
                Prompt.Completed completed = context.prompt.await(prompt);
                assertNotNull(completed, "the prompt completed");
                assertFalse(completed.dismissed, "the dialog was answered");
            }
            assertFalse(new Collection(collections.get(i), context.service.getConnection()).isLocked(),
                    collections.get(i) + " is unlocked again");
        }
    }

    @Test
    @EnabledIfSystemProperty(named = Dialogs.ANSWERED, matches = "true",
            disabledReason = "Locks every collection, the user's login keyring included, which only its password dialog unlocks again")
    @EnabledIfSystemProperty(named = Dialogs.DEFAULT_COLLECTION, matches = "throwaway",
            disabledReason = Dialogs.NOT_A_THROWAWAY_KEYRING)
    public void lockService() {
        context.ensureSession();
        assertTrue(context.service.lockService());

        Collection login = new Collection("login", context.service.getConnection());
        assertTrue(login.isLocked(), "the login keyring is locked");
        // Its dialog unlocks it again, so that the tests after this one find it unlocked.
        DBusPath prompt = context.service.unlock(List.of(login.getPath())).get().b;
        Prompt.Completed completed = context.prompt.await(prompt);
        assertNotNull(completed, "the prompt completed");
        assertFalse(completed.dismissed, "the dialog was answered");
        assertFalse(login.isLocked(), "the login keyring is unlocked again");
    }

    @Test
    public void changeLock() {
        context.ensureSession();

        DBusPath obj;
        DBusPath result;

        obj = new DBusPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        result = context.service.changeLock(obj).get();
        log.info(result.toString());
        assertTrue(result.getPath().startsWith("/org/freedesktop/secrets/prompt/"));

        obj = new DBusPath(Static.ObjectPaths.LOGIN_COLLECTION);
        result = context.service.changeLock(obj).get();
        log.info(result.toString());
        assertTrue(result.getPath().startsWith("/org/freedesktop/secrets/prompt/"));

        obj = new DBusPath(Static.ObjectPaths.SESSION_COLLECTION);
        result = context.service.changeLock(obj).get();
        log.info(result.toString());
        assertTrue(result.getPath().startsWith("/org/freedesktop/secrets/prompt/"));
    }

    @Test
    public void getSecrets() {
        context.ensureItem();

        List<DBusPath> items = context.collection.getItems().get();
        Map<DBusPath, Secret> result = context.service.getSecrets(items, context.session.getPath()).get();
        log.info(result.toString());

        assertEquals(1, result.size());
        // Read as declared: a Secret, not the struct as it arrived.
        Secret secret = result.values().iterator().next();
        assertEquals(context.session.getPath().getPath(), secret.getSession().getPath());
        // Keyed by the item's path, whoever sent it.
        assertNotNull(result.get(new DBusPath(items.get(0).getPath())), "found by the item's path");
    }

    @Test
    public void readAlias() {
        context.ensureCollection();

        DBusPath collection;

        collection = context.service.readAlias("default").get();
        log.info(collection.toString());
        assertEquals(Static.ObjectPaths.LOGIN_COLLECTION, collection.getPath(),
                "the default alias should point to the login collection");

        collection = context.service.readAlias("login").get();
        log.info(collection.toString());
        assertEquals(Static.ObjectPaths.LOGIN_COLLECTION, collection.getPath());

        collection = context.service.readAlias("session").get();
        log.info(collection.toString());
        assertEquals(Static.ObjectPaths.SESSION_COLLECTION, collection.getPath());

        collection = context.service.readAlias("test").get();
        log.info(collection.toString());
        assertEquals("/", collection.getPath(),
                "the test collection should not have an alias");
    }

    @Test
    // It points the default alias at the test collection: only where the default belongs to a
    // keyring of the run's own.
    @EnabledIfSystemProperty(named = Dialogs.DEFAULT_COLLECTION, matches = "throwaway",
            disabledReason = Dialogs.NOT_A_THROWAWAY_KEYRING)
    public void setAlias() {
        context.ensureCollection();

        DBusPath collection;
        DBusPath login = Static.Convert.toObjectPath(Static.ObjectPaths.LOGIN_COLLECTION);
        try {
            // change the default alias to point to the test collection
            context.service.setAlias("default", context.collection.getPath());
            collection = context.service.readAlias("default").get();
            log.info("default: " + collection);
            assertEquals(context.collection.getPath().getPath(), collection.getPath());
        } finally {
            // repair the default alias, also after a failure: the later tests use it
            context.service.setAlias("default", login);
        }
        collection = context.service.readAlias("default").get();
        log.info("default: " + collection);
        assertEquals(login.getPath(), collection.getPath());
    }

    @Test
    public void getCollections() {
        context.ensureCollection();

        List<DBusPath> collections = context.service.getCollections().get();
        log.info(Arrays.toString(collections.toArray()));

        List<String> cs = toStrings(collections);
        assertTrue(collections.size() >= 3);
        assertTrue(cs.contains("/org/freedesktop/secrets/collection/test"));
        assertTrue(cs.contains("/org/freedesktop/secrets/collection/login"));
        assertTrue(cs.contains("/org/freedesktop/secrets/collection/session"));
    }

    @Test
    public void isRemote() {
        context.ensureService();
        assertFalse(context.service.isRemote());
    }

    @Test
    public void getObjectPath() {
        context.ensureService();

        String result = context.service.getObjectPath();
        log.info(result);
        assertEquals("/org/freedesktop/secrets", result);
    }

}
