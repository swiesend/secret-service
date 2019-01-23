package org.freedesktop.secret.interfaces;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Pair;
import org.freedesktop.secret.Secret;
import org.freedesktop.secret.Static;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@DBusInterfaceName(Static.Interfaces.COLLECTION)
public abstract class Collection extends AbstractInterface implements DBusInterface {

    public static final String LABEL = "org.freedesktop.Secret.Collection.Label";

    public Collection(DBusConnection connection, List<Class> signals,
                      String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
    }

    public static Map<String, Variant> createProperties(String label) {
        HashMap<String, Variant> properties = new HashMap();
        properties.put(LABEL, new Variant(label));
        return properties;
    }

    public static class ItemCreated extends DBusSignal {
        public final DBusPath item;

        public ItemCreated(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

    public static class ItemDeleted extends DBusSignal {
        public final DBusPath item;

        public ItemDeleted(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

    public static class ItemChanged extends DBusSignal {
        public final DBusPath item;

        public ItemChanged(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

    abstract public ObjectPath delete();

    abstract public List<ObjectPath> searchItems(Map<String, String> attributes);

    abstract public Pair<ObjectPath, ObjectPath> createItem(Map<String, Variant> properties, Secret secret, boolean replace);

    abstract public List<ObjectPath> getItems();

    abstract public String getLabel();

    abstract public void setLabel(String label);

    abstract public boolean isLocked();

    abstract public UInt64 created();

    abstract public UInt64 modified();

}
