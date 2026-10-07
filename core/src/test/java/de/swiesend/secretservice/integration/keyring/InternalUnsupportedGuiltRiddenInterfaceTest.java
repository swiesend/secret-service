package de.swiesend.secretservice.integration.keyring;

import de.swiesend.secretservice.*;
import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;


public class InternalUnsupportedGuiltRiddenInterfaceTest {

    private static final Logger log = LoggerFactory.getLogger(InternalUnsupportedGuiltRiddenInterfaceTest.class);

    private DBusConnection connection;
    private Service service;
    private InternalUnsupportedGuiltRiddenInterface iugri;
    private Secret original;
    private Secret master;
    private Collection collection;

    @BeforeEach
    public void beforeEach() throws DBusException {
        connection = DBusConnectionBuilder.forSessionBus().withShared(false).build();
        service = new Service(connection);
        Pair<Variant<byte[]>, DBusPath> pair = service.openSession(Static.Algorithm.PLAIN, new Variant<>("")).get();
        DBusPath sessionPath = pair.b;
        iugri = new InternalUnsupportedGuiltRiddenInterface(service);
        original = new Secret(sessionPath, "".getBytes(), "test".getBytes());
        master = new Secret(sessionPath, "".getBytes(), "master-secret".getBytes());
        collection = new Collection("test", service.getConnection());
    }

    @AfterEach
    public void afterEach() throws InterruptedException {
        connection.disconnect();
        Thread.sleep(100L);
    }

    @Test
    public void changeWithMasterPassword() throws InterruptedException {

        List<DBusPath> collections = service.getCollections().get();
        List<String> cs = Static.Convert.toStrings(collections);
        if (!cs.contains("/org/freedesktop/secrets/collection/test")) {
            HashMap<String, Variant> properties = new HashMap<>();
            properties.put("org.freedesktop.Secret.Collection.Label", new Variant<>("test"));
            iugri.createWithMasterPassword(properties, original);
            Thread.sleep(100L);
        }

        iugri.changeWithMasterPassword(collection.getPath(), original, master);
        Thread.sleep(100L);

        List<DBusPath> lock = new ArrayList<>();
        lock.add(collection.getPath());
        service.lock(lock);
        Thread.sleep(100L);

        assertTrue(iugri.unlockWithMasterPassword(collection.getPath(), master));
        assertTrue(iugri.changeWithMasterPassword(collection.getPath(), master, original));
    }

    @Test
    @Disabled
    public void changeWithPrompt() throws InterruptedException {
        assertDoesNotThrow(() -> iugri.changeWithPrompt(collection.getPath()));
        Thread.sleep(1000L);
        // NOTE: no prompt popup. Is this to be expected?
    }

    @Test
    public void createWithMasterPassword() throws InterruptedException {

        List<DBusPath> collections = service.getCollections().get();
        List<String> cs = Static.Convert.toStrings(collections);

        if (cs.contains("/org/freedesktop/secrets/collection/test")) {
            DBusPath deleted = collection.delete().get();
            assertEquals("/", deleted.getPath());
            Thread.sleep(100L); // await signal: Service.CollectionDeleted
        }

        HashMap<String, Variant> properties = new HashMap<>();
        properties.put("org.freedesktop.Secret.Collection.Label", new Variant<>("test"));
        iugri.createWithMasterPassword(properties, original);
        Thread.sleep(100L); // await signal: Service.CollectionCreated

        collections = service.getCollections().get();
        cs = Static.Convert.toStrings(collections);

        assertTrue(cs.contains(Static.ObjectPaths.collection("test")));
    }

    @Test
    public void unlockWithMasterPassword() throws InterruptedException {
        List<DBusPath> lock = new ArrayList<>();
        lock.add(collection.getPath());
        service.lock(lock);
        Thread.sleep(100L); // await signal: Service.CollectionChanged

        assertDoesNotThrow(() -> iugri.unlockWithMasterPassword(collection.getPath(), original));
        Thread.sleep(100L); // await signal: Service.CollectionChanged
    }

    @Test
    public void isRemote() {
        assertFalse(iugri.isRemote());
    }
}