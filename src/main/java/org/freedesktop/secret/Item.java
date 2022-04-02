package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.handlers.Messaging;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class Item extends Messaging implements org.freedesktop.secret.interfaces.Item {

    private static final Logger log = LoggerFactory.getLogger(Item.class);

    private String id;

    public Item(String collectionID, String itemID, Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS,
                Static.ObjectPaths.item(collectionID, itemID),
                Static.Interfaces.ITEM);
        this.id = itemID;
    }

    public Item(ObjectPath item, Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS,
                item.getPath(),
                Static.Interfaces.ITEM);
        List<String> list = Arrays.asList(objectPath.split("/"));
        String itemID = list.get(list.size() - 1);
        this.id = itemID;
    }

    /**
     * Create properties for a new item.
     *
     * @param label      The displayable label of the item.
     * @param attributes String-valued attributes of the item.
     *
     *                   <p>
     *                   <b>Note:</b>
     *                   Please note that there is a distinction between the terms <i>Property</i>, which refers
     *                   to D-Bus properties of an object, and <i>Attribute</i>, which refers to one of a
     *                   secret item's string-valued attributes.
     *                   </p>
     * @return properties   &mdash; The properties for an item.
     *
     * <p>
     * <b>Example:</b><br>
     * <code>
     * properties = {<br>
     * &nbsp;&nbsp;"org.freedesktop.Secret.Item.Label": "MyItem",<br>
     * &nbsp;&nbsp;"org.freedesktop.Secret.Item.Attributes": {<br>
     * &nbsp;&nbsp;&nbsp;&nbsp;"Attribute1": "Value1",<br>
     * &nbsp;&nbsp;&nbsp;&nbsp;"Attribute2": "Value2"<br>
     * &nbsp;&nbsp;}<br>
     * }
     * </code>
     * </p>
     *
     * <p>
     * <b>Note:</b>
     * Properties for a collection and properties for an item are not the same.
     * </p>
     *
     * <br>
     * See Also:<br>
     * {@link org.freedesktop.secret.interfaces.Item#getAttributes()}<br>
     * {@link org.freedesktop.secret.interfaces.Item#setAttributes(Map attributes)}<br>
     * {@link org.freedesktop.secret.interfaces.Collection#createItem(Map properties, Secret secret, boolean replace)}<br>
     * {@link org.freedesktop.secret.Collection#createProperties(String label)}<br>
     * {@link org.freedesktop.secret.interfaces.Service#createCollection(Map properties)}<br>
     * {@link org.freedesktop.secret.interfaces.Service#createCollection(Map properties, String alias)}<br>
     */
    public static Map<String, Variant> createProperties(String label, Map<String, String> attributes) {
        Map<String, Variant> properties = new HashMap();
        properties.put(LABEL, new Variant(label));
        if (attributes != null) {
            properties.put(ATTRIBUTES, new Variant(attributes, "a{ss}"));
        }
        return properties;
    }

    @Override
    public Optional<ObjectPath> delete() {
        Object[] response = send("Delete", "").orElse(null);
        if (Static.Utils.isNullOrEmpty(response)) return Optional.empty();
        try {
            ObjectPath prompt = (ObjectPath) response[0];
            return Optional.of(prompt);
        } catch (ClassCastException e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<Secret> getSecret(ObjectPath session) {
        Object[] response = send("GetSecret", "o", session).orElse(null);
        if (Static.Utils.isNullOrEmpty(response)) return Optional.empty();
        try {
            Object[] inner = (Object[]) response[0];

            ObjectPath session_path = (ObjectPath) inner[0];
            byte[] parameters = Static.Convert.toByteArray((ArrayList<Byte>) inner[1]);
            byte[] value = Static.Convert.toByteArray((ArrayList<Byte>) inner[2]);
            String contentType = (String) inner[3];

            Secret secret;
            if (contentType.equals(Secret.TEXT_PLAIN) || contentType.equals(Secret.TEXT_PLAIN_CHARSET_UTF_8)) {
                // replace the content-type "text/plain" with default "text/plain; charset=utf8"
                secret = new Secret(session_path, parameters, value);
            } else {
                // use given non default content-type
                secret = new Secret(session_path, parameters, value, contentType);
            }

            return Optional.of(secret);
        } catch (ClassCastException | IndexOutOfBoundsException e) {
            return Optional.empty();
        }
    }

    @Override
    public boolean setSecret(Secret secret) {
        return send("SetSecret", "(oayays)", secret).isPresent();
    }

    @Override
    public boolean isLocked() {
        Optional<Boolean> response = getProperty("Locked").map(variant ->
                variant == null ? false : (boolean) variant.getValue());
        return response.isPresent() ? response.get() : false;
    }

    @Override
    public Optional<Map<String, String>> getAttributes() {
        return getProperty("Attributes").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((Map<String, String>) variant.getValue()));
    }

    @Override
    public boolean setAttributes(Map<String, String> attributes) {
        return setProperty("Attributes", new Variant(attributes, "a{ss}"));
    }

    @Override
    public Optional<String> getLabel() {
        return getProperty("Label").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((String) variant.getValue()));
    }

    @Override
    public boolean setLabel(String label) {
        return setProperty("Label", new Variant(label));
    }

    @Override
    public Optional<String> getType() {
        return getProperty("Type").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((String) variant.getValue()));
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
