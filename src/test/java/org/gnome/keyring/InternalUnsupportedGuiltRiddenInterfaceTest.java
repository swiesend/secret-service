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

import static org.junit.jupiter.api.Assertions.*;


public class InternalUnsupportedGuiltRiddenInterfaceTest {

    private DBusConnection connection;
    private Service service;
    private InternalUnsupportedGuiltRiddenInterface iugri;
    private Secret original;
    private Secret master;
    private Collection collection;

    @BeforeEach
    public void beforeEach() throws DBusException, InterruptedException {
        connection = DBusConnection.getConnection(DBusConnection.DBusBusType.SESSION);
        service = new Service(connection);
        service.openSession(Static.Algorithm.PLAIN, new Variant(""));
        iugri = new InternalUnsupportedGuiltRiddenInterface(service);
        original = new Secret(service.getSession().getPath(), "".getBytes(), "test".getBytes());
        master = new Secret(service.getSession().getPath(), "".getBytes(), "master-secret".getBytes());
        collection = new Collection("test", service);
        Thread.sleep(50L);
    }

    @AfterEach
    public void afterEach() throws InterruptedException {
        connection.disconnect();
        Thread.sleep(50L);
    }

    @Test
    public void changeWithMasterPassword() throws InterruptedException, DBusException {

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

        assertDoesNotThrow(() -> iugri.unlockWithMasterPassword(collection.getPath(), master));

        iugri.changeWithMasterPassword(collection.getPath(), master, original);
    }

    @Test
    @Disabled
    public void changeWithPrompt() throws DBusException {
        // NOTE: There is no prompt popup. This method behaves weird. Is this expected behavior?
        //       As the InternalUnsupportedGuiltRiddenInterface actually exists for not needing to use the prompt.
        assertDoesNotThrow(() -> iugri.changeWithPrompt(collection.getPath()));
    }

    @Test
    @Disabled
    public void createWithMasterPassword() throws InterruptedException, DBusException {

        List<ObjectPath> collections = service.getCollections();
        List<String> cs = Static.Convert.toStrings(collections);

        if (cs.contains("/org/freedesktop/secrets/collection/test")) {
            ObjectPath deleted = collection.delete();
            assertEquals("/", deleted.getPath());
            Thread.sleep(100L); // await signal: Service.CollectionDeleted
            assertEquals(Service.CollectionDeleted.class, service.getSignalHandler().getLastHandledSignal().get().getClass());
        }

        HashMap<String, Variant> properties = new HashMap();
        properties.put("org.freedesktop.Secret.Collection.Label", new Variant("test"));
        iugri.createWithMasterPassword(properties, original);
        Thread.sleep(100L); // await signal: Service.CollectionCreated
        assertEquals(Service.CollectionCreated.class, service.getSignalHandler().getLastHandledSignal().get().getClass());

        collections = service.getCollections();
        cs = Static.Convert.toStrings(collections);

        assertTrue(cs.contains(Static.ObjectPaths.collection("test")));
    }

    @Test
    @Disabled
    public void unlockWithMasterPassword() throws InterruptedException, DBusException {
        List<ObjectPath> lock = new ArrayList();
        lock.add(collection.getPath());

        service.lock(lock);
        Thread.sleep(100L); // await signal: Service.CollectionChanged
        assertEquals(Service.CollectionChanged.class, service.getSignalHandler().getLastHandledSignal().get().getClass());
        assertEquals(1, service.getSignalHandler().getCount());

        assertDoesNotThrow(() -> iugri.unlockWithMasterPassword(collection.getPath(), original));
        Thread.sleep(100L); // await signal: Service.CollectionChanged
        assertEquals(Service.CollectionChanged.class, service.getSignalHandler().getLastHandledSignal().get().getClass());
        assertEquals(2, service.getSignalHandler().getCount());
    }

    @Test
    public void isRemote() {
        assertFalse(iugri.isRemote());
    }
}
