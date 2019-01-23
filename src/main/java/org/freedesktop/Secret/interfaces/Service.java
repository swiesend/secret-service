package org.freedesktop.Secret.interfaces;

import org.freedesktop.Secret.Pair;
import org.freedesktop.Secret.Secret;
import org.freedesktop.Secret.Static;
import org.freedesktop.Secret.handlers.Messaging;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;

import java.util.List;
import java.util.Map;

@DBusInterfaceName(Static.Interfaces.SERVICE)
public abstract class Service extends Messaging implements DBusInterface {

    public Service(DBusConnection connection, List<Class> signals,
                   String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
    }

    public static class CollectionCreated extends DBusSignal {
        public final DBusPath collection;

        public CollectionCreated(String path, DBusPath collection) throws DBusException {
            super(path, collection);
            this.collection = collection;
        }
    }

    public static class CollectionDeleted extends DBusSignal {
        public final DBusPath collection;

        public CollectionDeleted(String path, DBusPath collection) throws DBusException {
            super(path, collection);
            this.collection = collection;
        }
    }

    public static class CollectionChanged extends DBusSignal {
        public final DBusPath collection;

        public CollectionChanged(String path, DBusPath collection) throws DBusException {
            super(path, collection);
            this.collection = collection;
        }
    }

    abstract public Pair<Variant<byte[]>, ObjectPath> openSession(String algorithm, Variant input);

    abstract public Pair createCollection(Map<String, Variant> properties, String alias);

    abstract public Pair<List<ObjectPath>, List<ObjectPath>> searchItems(Map<String, String> attributes);

    abstract public Pair<List<ObjectPath>, ObjectPath> unlock(List<ObjectPath> objects);

    abstract public Pair<List<ObjectPath>, ObjectPath> lock(List<ObjectPath> objects);

    abstract public void lockService();

    abstract public ObjectPath changeLock(ObjectPath collection);

    abstract public Map<ObjectPath, Secret> getSecrets(List<ObjectPath> items, DBusPath session);

    abstract public ObjectPath readAlias(String name);

    abstract public void setAlias(String name, ObjectPath collection);

    abstract public List<ObjectPath> getCollections();
}
