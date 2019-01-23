package org.gnome.keyring;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class InternalUnsupportedGuiltRiddenInterfaceTest {

    private DBusConnection connection;
    private Service service;
    private InternalUnsupportedGuiltRiddenInterface iugri;
    private Secret original;
    private Secret master;
    private Collection collection;

    @BeforeEach
    public void setUp() throws DBusException {
        connection = DBusConnection.getConnection(DBusConnection.DBusBusType.SESSION);
        service = new Service(connection);
        service.openSession(Static.Algorithm.PLAIN, new Variant(""));
        iugri = new InternalUnsupportedGuiltRiddenInterface(service);
        original = new Secret(service.getSession().getPath(), "".getBytes(), "test".getBytes());
        master = new Secret(service.getSession().getPath(), "".getBytes(), "master-secret".getBytes());
        collection = new Collection("test", service);
    }

    @AfterEach
    public void tearDown() throws InterruptedException {
        connection.disconnect();
        Thread.sleep(100L);
    }

    @Test
    public void changeWithMasterPassword() throws InterruptedException {

        List<ObjectPath> collections = service.getCollections();
        List<String> cs = Static.Convert.toStrings(collections);
        if (!cs.contains("/org/freedesktop/secrets/collection/test")) {
            HashMap<String, Variant> properties = new HashMap();
            properties.put("org.freedesktop.Secret.Collection.Label", new Variant("test"));
            iugri.createWithMasterPassword(properties, original);
            Thread.sleep(100L);
        }

        iugri.changeWithMasterPassword(collection.getPath(), original, master);
        Thread.sleep(100L);

        List<ObjectPath> lock = new ArrayList();
        lock.add(collection.getPath());
        service.lock(lock);
        iugri.unlockWithMasterPassword(collection.getPath(), master);

        iugri.changeWithMasterPassword(collection.getPath(), master, original);
    }

    @Test
    @Disabled
    public void changeWithPrompt() throws InterruptedException {
        iugri.changeWithPrompt(collection.getPath());
        Thread.sleep(1000L);
        // NOTE: no prompt popup. Is this to be expected?
    }

    @Test
    public void createWithMasterPassword() throws InterruptedException {

        List<ObjectPath> collections = service.getCollections();
        List<String> cs = Static.Convert.toStrings(collections);

        if (cs.contains("/org/freedesktop/secrets/collection/test")) {
            ObjectPath deleted = collection.delete();
            assertEquals("/", deleted.getPath());
            Thread.sleep(100L); // await signal: Service.CollectionDeleted
        }

        HashMap<String, Variant> properties = new HashMap();
        properties.put("org.freedesktop.Secret.Collection.Label", new Variant("test"));
        iugri.createWithMasterPassword(properties, original);
        Thread.sleep(100L); // await signal: Service.CollectionCreated

        collections = service.getCollections();
        cs = Static.Convert.toStrings(collections);

        assertTrue(cs.contains(Static.ObjectPaths.collection("test")));
    }

    @Test
    public void unlockWithMasterPassword() throws InterruptedException {
        List<ObjectPath> lock = new ArrayList();
        lock.add(collection.getPath());
        service.lock(lock);
        Thread.sleep(100L); // await signal: Service.CollectionChanged

        iugri.unlockWithMasterPassword(collection.getPath(), original);
        Thread.sleep(100L); // await signal: Service.CollectionChanged
    }

    @Test
    public void isRemote() {
        assertTrue(iugri.isRemote() == false);
    }
}