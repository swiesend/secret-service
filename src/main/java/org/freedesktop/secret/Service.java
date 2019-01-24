package org.freedesktop.secret;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.types.Variant;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Service extends org.freedesktop.secret.interfaces.Service {

    private Session session = null;

    public static final List<Class> signals = Arrays.asList(
            CollectionCreated.class, CollectionChanged.class, CollectionDeleted.class);

    public Service(DBusConnection connection) {
        super(connection, signals,
                Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS,
                Static.Interfaces.SERVICE);
    }

    @Override
    public Pair<Variant<byte[]>, ObjectPath> openSession(String algorithm, Variant input) {
        Object[] params = send("OpenSession", "sv", algorithm, input);
        session = new Session((ObjectPath) params[1], this);
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<ObjectPath, ObjectPath> createCollection(Map<String, Variant> properties, String alias) {
        if (alias == null) {
            alias = "";
        }
        Object[] params = send("CreateCollection", "a{sv}s", properties, alias);
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<ObjectPath, ObjectPath> createCollection(Map<String, Variant> properties) {
        return createCollection(properties, "");
    }

    @Override
    public Pair<List<ObjectPath>, List<ObjectPath>> searchItems(Map<String, String> attributes) {
        Object[] params = send("SearchItems", "a{ss}", attributes);
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<List<ObjectPath>, ObjectPath> unlock(List<ObjectPath> objects) {
        Object[] params = send("Unlock", "ao", objects);
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<List<ObjectPath>, ObjectPath> lock(List<ObjectPath> objects) {
        Object[] params = send("Lock", "ao", objects);
        return new Pair(params[0], params[1]);
    }

    @Override
    public void lockService() {
        send("LockService", "");
    }

    @Override
    public ObjectPath changeLock(ObjectPath collection) {
        Object[] params = send("ChangeLock", "o", collection);
        return (ObjectPath) params[0];
    }

    @Override
    public Map<ObjectPath, Secret> getSecrets(List<ObjectPath> items, ObjectPath session) {
        Object[] params = send("GetSecrets", "aoo", items, session);
        return (Map<ObjectPath, Secret>) params[0];
    }

    @Override
    public ObjectPath readAlias(String name) {
        Object[] params = send("ReadAlias", "s", name);
        return (ObjectPath) params[0];
    }

    @Override
    public void setAlias(String name, ObjectPath collection) {
        send("SetAlias", "so", name, collection);
    }

    @Override
    public List<ObjectPath> getCollections() {
        Variant response = getProperty("Collections");
        return (ArrayList<ObjectPath>) response.getValue();
    }

    @Override
    public boolean isRemote() {
        return false;
    }

    @Override
    public String getObjectPath() {
        return Static.ObjectPaths.SECRETS;
    }

    public Session getSession() {
        return session;
    }

}
