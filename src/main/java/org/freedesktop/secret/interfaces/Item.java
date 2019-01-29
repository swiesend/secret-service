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

    /**
     * The key of of the D-Bus properties for the label of an item.
     */
    public static final String LABEL = "org.freedesktop.Secret.Item.Label";

    /**
     * The key of the D-Bus properties for the attributes of an item.
     */
    public static final String ATTRIBUTES = "org.freedesktop.Secret.Item.Attributes";

    public Item(DBusConnection connection, List<Class> signals,
                String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
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
     * @see {@link Item#getAttributes()}
     * @see {@link Item#setAttributes(Map attributes)}
     * @see {@link Collection#createItem(Map properties, Secret secret, boolean replace)}
     * @see {@link Collection#createProperties(String label)}
     * @see {@link Service#createCollection(Map properties)}
     * @see {@link Service#createCollection(Map properties, String alias)}
     */
    public static Map<String, Variant> createProperties(String label, Map<String, String> attributes) {
        Map<String, Variant> properties = new HashMap();
        properties.put(LABEL, new Variant(label));
        if (attributes != null) {
            properties.put(ATTRIBUTES, new Variant(attributes, "a{ss}"));
        }
        return properties;
    }

    /**
     * Delete this item.
     * 
     * @return Prompt   &mdash; A prompt objectpath, or the special value '/' if no prompt is necessary.    
     */
    abstract public ObjectPath delete();

    /**
     * Retrieve the secret for this item.
     * 
     * @param session   The session to use to encode the secret.
     * 
     * @return secret   &mdash; The secret retrieved.
     */
    abstract public Secret getSecret(ObjectPath session);

    /**
     * Set the secret for this item.
     * 
     * @param secret    The secret to set, encoded for the included session.
     */
    abstract public void setSecret(Secret secret);

    /**
     * @return Whether the item is locked and requires authentication, or not.
     */
    abstract public boolean isLocked();

    /**
     * The lookup attributes for this item.
     * 
     * <b>Attributes</b> is a D-Bus Property.
     * 
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     * 
     * @return  The attributes of the item.
     */
    abstract public Map<String, String> getAttributes();

    
    /**
     * The lookup attributes for this item.
     * 
     * <b>Attributes</b> is a D-Bus Property.
     * 
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     * 
     * @param attributes    The attributes of the item.
     */
    abstract public void setAttributes(Map<String, String> attributes);

    /**
     * <b>Label</b> is a D-Bus Property.
     * 
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     * 
     * @return  The displayable label of this collection.
     *                  
     *  <p>
     *      <b>Note:</b>
     *      The displayable <code>label</code> can differ from the actual <code>name</code> of a collection.
     *  </p>
     */
    abstract public String getLabel();


    /**
     * <b>Label</b> is a D-Bus Property.
     * 
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     * 
     * @param  label    The displayable label of this collection.
     *                  
     *  <p>
     *      <b>Note:</b>
     *      The displayable <code>label</code> can differ from the actual <code>name</code> of a collection.
     *  </p>
     */
    abstract public void setLabel(String label);

    /**
     * @return The "xdg:schema" of the item attributes.
     */
    abstract public String getType();

    /**
     * @return The unix time when the item was created.
     */
    abstract public UInt64 created();

    /**
     * @return The unix time when the item was last modified.
     */
    abstract public UInt64 modified();
}
