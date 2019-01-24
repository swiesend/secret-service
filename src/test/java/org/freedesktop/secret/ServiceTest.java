package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.errors.NoSuchObject;
import org.freedesktop.secret.test.Context;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static org.freedesktop.secret.Static.Convert.toStrings;
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

        Pair<Variant<byte[]>, ObjectPath> response = context.service.openSession(Static.Algorithm.PLAIN, new Variant(""));
        log.info(response.toString());

        assertEquals("s", response.a.getSig());
        assertEquals("", response.a.getValue(), "the value of an empty byte[] behaves odd as it returns a String.");

        ObjectPath sessionPath = response.b;
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

        Pair<Variant<byte[]>, ObjectPath> response = context.service.openSession(
                Static.Algorithm.DH_IETF_1024_SHA_256_AES_128_CBC_PKCS_7, new Variant(input));
        log.info(response.toString());

        byte[] peerPublicKey = response.a.getValue();
        assertEquals(128, peerPublicKey.length);

        ObjectPath sessionPath = response.b;
        assertTrue(sessionPath.getPath().startsWith(Static.ObjectPaths.SESSION + "/s"));
    }

    @Test
    @Disabled
    public void createCollection() throws InterruptedException, NoSuchObject {
        context.ensureCollection();

        ObjectPath deletePrompt = context.collection.delete();
        if (!deletePrompt.getPath().equals("/")) {
            context.prompt.await(deletePrompt);
        }

        List<ObjectPath> before = context.service.getCollections();

        Map<String, Variant> properties = Collection.createProperties("test");
        Pair<ObjectPath, ObjectPath> response = context.service.createCollection(properties);
        log.info(response.toString());

        ObjectPath collectionPath = response.a;
        ObjectPath createPrompt = response.b;
        if (collectionPath.getPath().equals("/")) {
            assertTrue(createPrompt.getPath().startsWith("/org/freedesktop/secrets/prompt/p"));
            context.prompt.await(createPrompt);
        } else {
            assertEquals("/", createPrompt.getPath());
        }

        List<ObjectPath> after = context.service.getCollections();
        DBusSignal[] handled = context.prompt.getSignalHandler().getHandled();
        Prompt.Completed completed = (Prompt.Completed) handled[0];
        if (completed.dismissed) {
            assertEquals(before.size(), after.size());
        } else {
            assertEquals(before.size() + 1, after.size());
        }
    }

    @Test
    public void searchItems() {
        context.ensureItem();

        Map<String, String> attributes = new HashMap();
        attributes.put("Attribute1", "Value1");

        Pair<List<ObjectPath>, List<ObjectPath>> response = context.service.searchItems(attributes);
        List<String> unlocked = toStrings(response.a);
        List<String> locked = toStrings(response.b);

        assertTrue(unlocked.size() >= 0);
        assertTrue(unlocked.get(0).startsWith("/org/freedesktop/secrets/collection/test/"));
        assertTrue(locked.isEmpty());
    }

    @Test
    @Disabled
    public void unlockCollectionsOrItems() throws InterruptedException, NoSuchObject {

        Pair<List<ObjectPath>, ObjectPath> response;
        List<ObjectPath> locked, unlocked;
        ObjectPath prompt;
        Prompt.Completed completed;

        // unlock a collection
        context.ensureCollection();

        ArrayList<ObjectPath> lockable = new ArrayList();
        lockable.add(context.collection.getPath());

        response = context.service.lock(lockable);
        log.info(response.toString());
        locked = response.a;
        assertEquals(1, locked.size());
        prompt = response.b;
        assertEquals("/", prompt.getPath());

        response = context.service.unlock(lockable);
        log.info(response.toString());
        unlocked = response.a;
        assertEquals(0, unlocked.size());
        prompt = response.b;
        context.prompt.await(prompt);
        completed = context.prompt.getLastHandledSignal();
        if (completed.dismissed) {
            assertTrue(context.collection.isLocked());
        } else {
            assertFalse(context.collection.isLocked());
        }

        // unlock an item
        context.after();
        context.ensureItem();

        List<ObjectPath> items = context.collection.getItems();

        response = context.service.lock(items);
        log.info(response.toString());
        locked = response.a;
        assertEquals(1, locked.size());
        prompt = response.b;
        assertEquals("/", prompt.getPath());

        response = context.service.unlock(items);
        log.info(response.toString());
        unlocked = response.a;
        assertEquals(0, unlocked.size());
        prompt = response.b;
        context.prompt.await(prompt);
        completed = context.prompt.getLastHandledSignal();
        if (completed.dismissed) {
            assertTrue(context.item.isLocked());
        } else {
            assertFalse(context.item.isLocked());
        }

    }

    @Test
    @Disabled
    public void lockCommonCollections() throws InterruptedException, NoSuchObject {

        // lock common collections:
        //   * alias/default == collection/login
        //   * collection/login
        //   * collection/session
        context.ensureSession();

        ArrayList<ObjectPath> objects = new ArrayList();
        objects.add(Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION));
        objects.add(Static.Convert.toObjectPath(Static.ObjectPaths.LOGIN_COLLECTION));
        objects.add(Static.Convert.toObjectPath(Static.ObjectPaths.SESSION_COLLECTION));

        Pair<List<ObjectPath>, ObjectPath> response = context.service.lock(objects);
        log.info(response.toString());

        List<ObjectPath> locked = response.a;
        assertEquals(Static.ObjectPaths.DEFAULT_COLLECTION, locked.get(0).getPath());
        assertEquals(Static.ObjectPaths.LOGIN_COLLECTION, locked.get(1).getPath());
        assertEquals(Static.ObjectPaths.SESSION_COLLECTION, locked.get(2).getPath());

        ObjectPath prompt = response.b;
        assertEquals("/", prompt.getPath());

        for (int i = 0; i < objects.size(); i++) {
            List<ObjectPath> unlock = Arrays.asList(new ObjectPath[]{objects.get(i)});
            response = context.service.unlock(unlock);
            prompt = response.b;
            if (!prompt.getPath().equals("/")) {
                context.prompt.await(prompt);
            }
        }
    }

    @Test
    @Disabled
    public void lockService() {
        context.ensureSession();
        context.service.lockService();
    }

    @Test
    public void changeLock() {
        context.ensureSession();

        ObjectPath obj, result;

        obj = new ObjectPath("", Static.ObjectPaths.DEFAULT_COLLECTION);
        result = context.service.changeLock(obj);
        log.info(result.toString());
        assertTrue(result.getPath().startsWith("/org/freedesktop/secrets/prompt/"));


        obj = new ObjectPath("", Static.ObjectPaths.LOGIN_COLLECTION);
        result = context.service.changeLock(obj);
        log.info(result.toString());
        assertTrue(result.getPath().startsWith("/org/freedesktop/secrets/prompt/"));


        obj = new ObjectPath("", Static.ObjectPaths.SESSION_COLLECTION);
        result = context.service.changeLock(obj);
        log.info(result.toString());
        assertTrue(result.getPath().startsWith("/org/freedesktop/secrets/prompt/"));
    }

    @Test
    public void getSecrets() {
        context.ensureItem();

        List<ObjectPath> items = context.collection.getItems();
        Map<ObjectPath, Secret> result = context.service.getSecrets(items, context.session.getPath());
        log.info(result.toString());

        assertEquals(1, result.size());
    }

    @Test
    public void readAlias() {
        context.ensureCollection();

        ObjectPath collection;

        collection = context.service.readAlias("default");
        log.info(collection.toString());
        assertEquals(Static.ObjectPaths.LOGIN_COLLECTION, collection.getPath(),
                "the default alias should point to the login collection");

        collection = context.service.readAlias("login");
        log.info(collection.toString());
        assertEquals(Static.ObjectPaths.LOGIN_COLLECTION, collection.getPath());

        collection = context.service.readAlias("session");
        log.info(collection.toString());
        assertEquals(Static.ObjectPaths.SESSION_COLLECTION, collection.getPath());

        collection = context.service.readAlias("test");
        log.info(collection.toString());
        assertEquals("/", collection.getPath(),
                "the test collection should not have an alias");
    }

    @Test
    @Disabled
    public void setAlias() {
        context.ensureCollection();

        ObjectPath collection;

        // change the default alias to point to the test collection
        context.service.setAlias("default", context.collection.getPath());
        collection = context.service.readAlias("default");
        log.info("default: " + collection);
        assertEquals(context.collection.getPath().getPath(), collection.getPath());

        // repair the default alias
        ObjectPath login = Static.Convert.toObjectPath(Static.ObjectPaths.LOGIN_COLLECTION);
        context.service.setAlias("default", login);
        collection = context.service.readAlias("default");
        log.info("default: " + collection);
        assertEquals(login.getPath(), collection.getPath());
    }

    @Test
    public void getCollections() {
        context.ensureCollection();

        List<ObjectPath> collections = context.service.getCollections();
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
