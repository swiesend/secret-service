package de.swiesend.secretservice;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.handlers.Messaging;

import java.util.*;

public class Collection extends Messaging implements org.freedesktop.secret.interfaces.Collection {

    private String id;

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(
            ItemCreated.class, ItemChanged.class, ItemDeleted.class);

    public Collection(DBusPath path, Service service) {
        super(service.getConnection(), signals,
                Static.Service.SECRETS,
                path.getPath(),
                Static.Interfaces.COLLECTION);
        String[] split = path.getPath().split("/");
        this.id = split[split.length - 1];
    }

    public Collection(DBusPath path, Service service, List<Class<? extends DBusSignal>> signals) {
        super(service.getConnection(), signals,
                Static.Service.SECRETS,
                path.getPath(),
                Static.Interfaces.COLLECTION);
        String[] split = path.getPath().split("/");
        this.id = split[split.length - 1];
    }

    public Collection(String id, Service service) {
        super(service.getConnection(), signals,
                Static.Service.SECRETS,
                Static.ObjectPaths.collection(id),
                Static.Interfaces.COLLECTION);
        this.id = id;
    }

    /**
     * Create propterties for a new collection.
     *
     * @param label The displayable label of this collection.
     *
     *  <p>
     *      <b>Note:</b>
     *      The displayable <code>label</code> can differ from the actual <code>name</code> of a collection.
     *  </p>
     *
     * @return properties   &mdash; The propterties for a collection.
     *
     *  <p><code>{org.freedesktop.Secret.Collection.Label: label}</code></p>
     *
     *  <p>
     *      <b>Note:</b>
     *      Properties for a collection and properties for an item are not the same.
     *  </p>
     *
     *  <br>
     *  See Also:<br>
     *  {@link Collection#createItem(Map properties, Secret secret, boolean replace)}<br>
     *  {@link Service#createCollection(Map properties)}<br>
     *  {@link Service#createCollection(Map properties, String alias)}<br>
     *  {@link Item#createProperties(String label, Map attributes)}<br>
     */
    public static Map<String, Variant> createProperties(String label) {
        HashMap<String, Variant> properties = new HashMap();
        properties.put(LABEL, new Variant(label));
        return properties;
    }

    @Override
    public ObjectPath delete() {
        Object[] response = send("Delete", "");
        if (response == null) return null;
        ObjectPath prompt = (ObjectPath) response[0];
        return prompt;
    }

    @Override
    public List<ObjectPath> searchItems(Map<String, String> attributes) {
        Object[] response = send("SearchItems", "a{ss}", attributes);
        if (response == null) return null;
        return (List<ObjectPath>) response[0];
    }

    @Override
    public Pair<ObjectPath, ObjectPath> createItem(Map<String, Variant> properties, Secret secret,
                                                   boolean replace) {
        Object[] response = send("CreateItem", "a{sv}(oayays)b", properties, secret, replace);
        if (response == null) return null;
        return new Pair(response[0], response[1]);
    }

    @Override
    public List<ObjectPath> getItems() {
        Variant response = getProperty("Items");
        if (response == null) return null;
        return (ArrayList<ObjectPath>) response.getValue();
    }

    @Override
    public String getLabel() {
        Variant response = getProperty("Label");
        if (response == null) return null;
        return (String) response.getValue();
    }

    @Override
    public void setLabel(String label) {
        setProperty("Label", new Variant(label));
    }

    @Override
    public boolean isLocked() {
        Variant response = getProperty("Locked");
        if (response == null) return true;
        return (boolean) response.getValue();
    }

    @Override
    public UInt64 created() {
        Variant response = getProperty("Created");
        if (response == null) return null;
        return (UInt64) response.getValue();
    }

    @Override
    public UInt64 modified() {
        Variant response = getProperty("Modified");
        if (response == null) return null;
        return (UInt64) response.getValue();
    }

    @Override
    public boolean isRemote() {
        return false;
    }

    @Override
    public String getObjectPath() {
        return super.getObjectPath();
    }

    public String getId() {
        return id;
    }

}
