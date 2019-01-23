package org.freedesktop.secret.interfaces;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Secret;
import org.freedesktop.secret.Static;
import org.freedesktop.secret.handlers.Messaging;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@DBusInterfaceName(Static.Interfaces.ITEM)
public abstract class Item extends Messaging implements DBusInterface {
    public static final String LABEL = "org.freedesktop.Secret.Item.Label";
    public static final String ATTRIBUTES = "org.freedesktop.Secret.Item.Attributes";

    public Item(DBusConnection connection, List<Class> signals,
                String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
    }

    public static Map<String, Variant> createProperties(String label, Map<String, String> attributes) {
        Map<String, Variant> properties = new HashMap();
        properties.put(LABEL, new Variant(label));
        properties.put(ATTRIBUTES, new Variant(attributes, "a{ss}"));
        return properties;
    }

    abstract public ObjectPath delete();

    abstract public Secret getSecret(ObjectPath session);

    abstract public void setSecret(Secret secret);

    abstract public boolean isLocked();

    abstract public Map<String, String> getAttributes();

    abstract public void setAttributes(Map<String, String> attributes);

    abstract public String getLabel();

    abstract public void setLabel(String label);

    abstract public String getType();

    abstract public UInt64 created();

    abstract public UInt64 modified();
}
