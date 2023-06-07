package de.swiesend.secretservice;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.handlers.Messaging;

import java.util.*;

public class Item extends Messaging implements org.freedesktop.secret.interfaces.Item {

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
     * @param label         The displayable label of the item.
     *
     * @param attributes    String-valued attributes of the item.
     *
     *                      <p>
     *                          <b>Note:</b>
     *                          Please note that there is a distinction between the terms <i>Property</i>, which refers
     *                          to D-Bus properties of an object, and <i>Attribute</i>, which refers to one of a
     *                          secret item's string-valued attributes.
     *                      </p>
     *
     * @return properties   &mdash; The properties for an item.
     *
     *  <p>
     *      <b>Example:</b><br>
     *      <code>
     *      properties = {<br>
     *          &nbsp;&nbsp;"org.freedesktop.Secret.Item.Label": "MyItem",<br>
     *          &nbsp;&nbsp;"org.freedesktop.Secret.Item.Attributes": {<br>
     *          &nbsp;&nbsp;&nbsp;&nbsp;"Attribute1": "Value1",<br>
     *          &nbsp;&nbsp;&nbsp;&nbsp;"Attribute2": "Value2"<br>
     *          &nbsp;&nbsp;}<br>
     *      }
     *      </code>
     *  </p>
     *
     *  <p>
     *      <b>Note:</b>
     *      Properties for a collection and properties for an item are not the same.
     *  </p>
     *
     *  <br>
     *  See Also:<br>
     *      {@link org.freedesktop.secret.interfaces.Item#getAttributes()}<br>
     *      {@link org.freedesktop.secret.interfaces.Item#setAttributes(Map attributes)}<br>
     *      {@link org.freedesktop.secret.interfaces.Collection#createItem(Map properties, Secret secret, boolean replace)}<br>
     *      {@link Collection#createProperties(String label)}<br>
     *      {@link org.freedesktop.secret.interfaces.Service#createCollection(Map properties)}<br>
     *      {@link org.freedesktop.secret.interfaces.Service#createCollection(Map properties, String alias)}<br>
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
    public ObjectPath delete() {
        Object[] response = send("Delete", "");
        if (response == null) return null;
        ObjectPath prompt = (ObjectPath) response[0];
        return prompt;
    }

    @Override
    public Secret getSecret(ObjectPath session) {
        Object[] response = send("GetSecret", "o", session);
        if (response == null) return null;
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

            return secret;
        } catch (ClassCastException | IndexOutOfBoundsException e) {
            return null;
        }
    }

    @Override
    public void setSecret(Secret secret) {
        send("SetSecret", "(oayays)", secret);
    }

    @Override
    public boolean isLocked() {
        Variant response = getProperty("Locked");
        if (response == null) return true;
        return (boolean) response.getValue();
    }

    @Override
    public Map<String, String> getAttributes() {
        Variant response = getProperty("Attributes");
        if (response == null) return null;
        return (Map<String, String>) response.getValue();
    }

    @Override
    public void setAttributes(Map<String, String> attributes) {
        setProperty("Attributes", new Variant(attributes, "a{ss}"));
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
    public String getType() {
        Variant response = getProperty("Type");
        if (response == null) return null;
        return (String) response.getValue();
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
