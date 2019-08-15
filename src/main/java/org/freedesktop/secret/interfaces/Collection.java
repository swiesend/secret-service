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

    /**
     * The key of the D-Bus properties for the label of a collection.
     */
    public static final String LABEL = "org.freedesktop.Secret.Collection.Label";

    public Collection(DBusConnection connection, List<Class<? extends DBusSignal>> signals,
                      String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
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
     * @see {@link Service#createCollection(Map properties)}
     * @see {@link Service#createCollection(Map properties, String alias)}
     * @see {@link Item#createProperties(String label, Map attributes)}
     * @see {@link Collection#createItem(Map properties, Secret secret, boolean replace)}
     */
    public static Map<String, Variant> createProperties(String label) {
        HashMap<String, Variant> properties = new HashMap();
        properties.put(LABEL, new Variant(label));
        return properties;
    }

    public static class ItemCreated extends DBusSignal {
        public final DBusPath item;

        /**
         * A new item in this collection was created.
         * 
         * @param path  The path to the object this is emitted from.
         * @param item  The item that was created.
         * 
         * @throws DBusException
         */
        public ItemCreated(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

    public static class ItemDeleted extends DBusSignal {
        public final DBusPath item;

        /**
         * An item in this collection was deleted.
         *   
         * @param path  The path to the object this is emitted from.
         * @param item  The item that was deleted.
         * 
         * @throws DBusException
         */
        public ItemDeleted(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

    public static class ItemChanged extends DBusSignal {
        public final DBusPath item;

        /**
         * An item in this collection changed.
         *   
         * @param path  The path to the object this is emitted from.
         * @param item  The item that was changed.
         * 
         * @throws DBusException
         */
        public ItemChanged(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

    /**
     * Delete this collection.
     * 
     * @return prompt   &mdash; A prompt to delete the collection, or the special value '/' when no prompt is necessary.
     * 
     * @see ObjectPath
     */
    abstract public ObjectPath delete() throws DBusException;

    /**
     * Search for items in this collection matching the lookup attributes.
     * 
     * @param attributes   Attributes to match.
     * 
     * @return results     &mdash; Items that matched the attributes.
     * 
     * @see ObjectPath
     * @see Secret
     * @see Item
     */
    abstract public List<ObjectPath> searchItems(Map<String, String> attributes) throws DBusException;

    /**
     * Create an item with the given attributes, secret and label. If replace is set, then it replaces an item already 
     * present with the same values for the attributes.
     * 
     * @param  properties   The properties for the new item.
     *                      
     *                      <p>This allows setting the new item's properties upon its creation. All READWRITE properties 
     *                      are useable. Specify the property names in full <code>interface.Property</code> form.</p>
     * 
     *                      <p>
     *                          <b>Example 13.2. Example for properties of an item:</b><br>
     *                          <code>
     *                          properties = {<br>
     *                              &nbsp;&nbsp;"org.freedesktop.Secret.Item.Label": "MyItem",<br>
     *                              &nbsp;&nbsp;"org.freedesktop.Secret.Item.Attributes": {<br>
     *                              &nbsp;&nbsp;&nbsp;&nbsp;"Attribute1": "Value1",<br>
     *                              &nbsp;&nbsp;&nbsp;&nbsp;"Attribute2": "Value2"<br>
     *                              &nbsp;&nbsp;}<br>
     *                          }<br>
     *                      </code></p>
     * 
     *                      <p>
     *                          <b>Note:</b>
     *                          Please note that there is a distinction between the terms <i>Property</i>, which refers 
     *                          to D-Bus properties of an object, and <i>Attribute</i>, which refers to one of a 
     *                          secret item's string-valued attributes. 
     *                      </p>
     * 
     * @param secret        The secret to store in the item, encoded with the included session.
     * 
     * @param replace       Whether to replace an item with the same attributes or not.
     * 
     * @return Pair&lt;item, prompt&gt;<br>
     * <br>
     * item                 &mdash; The item created, or the special value '/' if a prompt is necessary.<br>
     * <br>
     * prompt               &mdash; A prompt object, or the special value '/' if no prompt is necessary.<br>
     * 
     * @see static {@link Collection#createProperties(String label)}}
     * @see static {@link Item#createProperties(String label, Map attributes)}}
     * @see Pair
     * @see ObjectPath
     * @see Secret
     * @see Item
     */
    abstract public Pair<ObjectPath, ObjectPath> createItem(Map<String, Variant> properties, Secret secret, boolean replace) throws DBusException;

    /**
     * <b>Items</b> is a D-Bus Property.
     * 
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     * 
     * @return  Items in this collection.
     */
    abstract public List<ObjectPath> getItems() throws DBusException;

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
    abstract public String getLabel() throws DBusException;

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
    abstract public void setLabel(String label) throws DBusException;

    /**
     * @return  Whether the collection is locked and must be authenticated by the client application. 
     */
    abstract public boolean isLocked() throws DBusException;

    /**
     * @return  The unix time when the collection was created.
     */
    abstract public UInt64 created() throws DBusException;

    /**
     * @return  The unix time when the collection was last modified.
     */
    abstract public UInt64 modified() throws DBusException;

}
