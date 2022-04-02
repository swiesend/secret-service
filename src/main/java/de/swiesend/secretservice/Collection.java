package de.swiesend.secretservice;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Static.Utils;
import de.swiesend.secretservice.handlers.Messaging;

import java.util.*;

public class Collection extends Messaging implements de.swiesend.secretservice.interfaces.Collection {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(
            ItemCreated.class, ItemChanged.class, ItemDeleted.class);
    private String id;

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
        properties.put(LABEL, new Variant<>(label));
        return properties;
    }

    @Override
    public Optional<ObjectPath> delete() {
        Optional<ObjectPath> prompt = send("Delete", "").flatMap(response ->
                Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((ObjectPath) response[0])
        );
        return prompt;
    }

    @Override
    public Optional<List<ObjectPath>> searchItems(Map<String, String> attributes) {
        return send("SearchItems", "a{ss}", attributes).flatMap(response ->
                Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((List<ObjectPath>) response[0])
        );
    }

    @Override
    public Optional<Pair<ObjectPath, ObjectPath>> createItem(Map<String, Variant> properties, Secret secret, boolean replace) {
        return send("CreateItem", "a{sv}(oayays)b", properties, secret, replace).flatMap(response ->
                (Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<ObjectPath, ObjectPath>((ObjectPath) response[0], (ObjectPath) response[1])));
    }

    @Override
    public Optional<List<ObjectPath>> getItems() {
        return getProperty("Items").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((List<ObjectPath>) variant.getValue())
        );
    }

    @Override
    public Optional<String> getLabel() {
        return getProperty("Label").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((String) variant.getValue())
        );
    }

    @Override
    public boolean setLabel(String label) {
        return setProperty("Label", new Variant(label));
    }

    @Override
    public boolean isLocked() {
        Optional<Boolean> response = getProperty("Locked").map(variant ->
                variant == null ? false : (boolean) variant.getValue());
        return response.isPresent() ? response.get() : false;
    }

    @Override
    public Optional<UInt64> created() {
        return getProperty("Created").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((UInt64) variant.getValue()));
    }

    @Override
    public Optional<UInt64> modified() {
        return getProperty("Modified").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((UInt64) variant.getValue()));
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
