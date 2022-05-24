package org.gnome.keyring;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Collection;
import org.freedesktop.secret.Secret;
import org.freedesktop.secret.Service;
import org.freedesktop.secret.Static;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;


public class InternalUnsupportedGuiltRiddenInterfaceTest {

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
        service.openSession(Static.Algorithm.PLAIN, new Variant(""));
        iugri = new InternalUnsupportedGuiltRiddenInterface(service);
        original = new Secret(service.getSession().getPath(), "".getBytes(), "test".getBytes());
        master = new Secret(service.getSession().getPath(), "".getBytes(), "master-secret".getBytes());
        collection = new Collection("test", service);
    }

    @AfterEach
    public void afterEach() throws InterruptedException {
        connection.disconnect();
        Thread.currentThread().sleep(100L);
    }

    @Test
    public void changeWithMasterPassword() throws InterruptedException {

        List<ObjectPath> collections = service.getCollections().get();
        List<String> cs = Static.Convert.toStrings(collections);
        if (!cs.contains("/org/freedesktop/secrets/collection/test")) {
            HashMap<String, Variant> properties = new HashMap();
            properties.put("org.freedesktop.Secret.Collection.Label", new Variant("test"));
            iugri.createWithMasterPassword(properties, original);
            Thread.currentThread().sleep(100L);
        }

        iugri.changeWithMasterPassword(collection.getPath(), original, master);
        Thread.currentThread().sleep(100L);

        List<ObjectPath> lock = new ArrayList();
        lock.add(collection.getPath());
        service.lock(lock);

        assertDoesNotThrow(() -> iugri.unlockWithMasterPassword(collection.getPath(), master));

        iugri.changeWithMasterPassword(collection.getPath(), master, original);
    }

    @Test
    @Disabled
    public void changeWithPrompt() throws InterruptedException {
        assertDoesNotThrow(() -> iugri.changeWithPrompt(collection.getPath()));
        Thread.currentThread().sleep(1000L);
        // NOTE: no prompt popup. Is this to be expected?
    }

    @Test
    public void createWithMasterPassword() throws InterruptedException {

        List<ObjectPath> collections = service.getCollections().get();
        List<String> cs = Static.Convert.toStrings(collections);

        if (cs.contains("/org/freedesktop/secrets/collection/test")) {
            ObjectPath deleted = collection.delete().get();
            assertEquals("/", deleted.getPath());
            Thread.currentThread().sleep(100L); // await signal: Service.CollectionDeleted
        }

        HashMap<String, Variant> properties = new HashMap();
        properties.put("org.freedesktop.Secret.Collection.Label", new Variant("test"));
        iugri.createWithMasterPassword(properties, original);
        Thread.currentThread().sleep(100L); // await signal: Service.CollectionCreated

        collections = service.getCollections().get();
        cs = Static.Convert.toStrings(collections);

        assertTrue(cs.contains(Static.ObjectPaths.collection("test")));
    }

    @Test
    public void unlockWithMasterPassword() throws InterruptedException {
        List<ObjectPath> lock = new ArrayList();
        lock.add(collection.getPath());
        service.lock(lock);
        Thread.currentThread().sleep(100L); // await signal: Service.CollectionChanged

        assertDoesNotThrow(() -> iugri.unlockWithMasterPassword(collection.getPath(), original));
        Thread.currentThread().sleep(100L); // await signal: Service.CollectionChanged
    }

    @Test
    public void isRemote() {
        assertFalse(iugri.isRemote());
    }
}