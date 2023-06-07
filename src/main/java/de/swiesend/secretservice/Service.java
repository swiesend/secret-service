package de.swiesend.secretservice;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.handlers.Messaging;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Service extends Messaging implements org.freedesktop.secret.interfaces.Service {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(
            CollectionCreated.class, CollectionChanged.class, CollectionDeleted.class);
    private Session session = null;

    public Service(DBusConnection connection) {
        super(connection, signals,
                Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS,
                Static.Interfaces.SERVICE);
    }

    @Override
    public Pair<Variant<byte[]>, ObjectPath> openSession(String algorithm, Variant input) {
        Object[] params = send("OpenSession", "sv", algorithm, input);
        if (params == null) return null;
        session = new Session((ObjectPath) params[1], this);
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<ObjectPath, ObjectPath> createCollection(Map<String, Variant> properties, String alias) {
        String a;
        if (alias == null) {
            a = "";
        } else {
            a = alias;
        }
        Object[] params = send("CreateCollection", "a{sv}s", properties, a);
        if (params == null) return null;
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<ObjectPath, ObjectPath> createCollection(Map<String, Variant> properties) {
        return createCollection(properties, "");
    }

    @Override
    public Pair<List<ObjectPath>, List<ObjectPath>> searchItems(Map<String, String> attributes) {
        Object[] params = send("SearchItems", "a{ss}", attributes);
        if (params == null) return null;
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<List<ObjectPath>, ObjectPath> unlock(List<ObjectPath> objects) {
        Object[] params = send("Unlock", "ao", objects);
        if (params == null) return null;
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<List<ObjectPath>, ObjectPath> lock(List<ObjectPath> objects) {
        Object[] params = send("Lock", "ao", objects);
        if (params == null) return null;
        return new Pair(params[0], params[1]);
    }

    @Override
    public void lockService() {
        send("LockService", "");
    }

    @Override
    public ObjectPath changeLock(ObjectPath collection) {
        Object[] params = send("ChangeLock", "o", collection);
        if (params == null) return null;
        return (ObjectPath) params[0];
    }

    @Override
    public Map<ObjectPath, Secret> getSecrets(List<ObjectPath> items, ObjectPath session) {
        Object[] params = send("GetSecrets", "aoo", items, session);
        if (params == null) return null;
        return (Map<ObjectPath, Secret>) params[0];
    }

    @Override
    public ObjectPath readAlias(String name) {
        Object[] params = send("ReadAlias", "s", name);
        if (params == null) return null;
        return (ObjectPath) params[0];
    }

    @Override
    public void setAlias(String name, ObjectPath collection) {
        send("SetAlias", "so", name, collection);
    }

    @Override
    public List<ObjectPath> getCollections() {
        Variant response = getProperty("Collections");
        if (response == null) return null;
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
