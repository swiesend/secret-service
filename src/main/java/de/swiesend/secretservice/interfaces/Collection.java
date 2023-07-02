package de.swiesend.secretservice.interfaces;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Pair;
import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.Static;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@DBusInterfaceName(Static.Interfaces.COLLECTION)
public interface Collection extends DBusInterface {

    /**
     * The key of the D-Bus properties for the label of a collection.
     */
    String LABEL = "org.freedesktop.Secret.Collection.Label";

    /**
     * Delete this collection.
     *
     * @return prompt   &mdash; A prompt to delete the collection, or the special value '/' when no prompt is necessary.
     * @see ObjectPath
     */
    Optional<ObjectPath> delete();

    /**
     * Search for items in this collection matching the lookup attributes.
     *
     * @param attributes Attributes to match.
     * @return results     &mdash; Items that matched the attributes.
     * @see ObjectPath
     * @see Secret
     * @see Item
     */
    Optional<List<ObjectPath>> searchItems(Map<String, String> attributes);

    /**
     * Create an item with the given attributes, secret and label. If replace is set, then it replaces an item already
     * present with the same values for the attributes.
     *
     * @param properties The properties for the new item.
     *
     *                   <p>This allows setting the new item's properties upon its creation. All READWRITE properties
     *                   are usable. Specify the property names in full <code>interface.Property</code> form.</p>
     *
     *                   <p>
     *                   <b>Example 13.2. Example for properties of an item:</b><br>
     *                   <code>
     *                   properties = {<br>
     *                   &nbsp;&nbsp;"org.freedesktop.Secret.Item.Label": "MyItem",<br>
     *                   &nbsp;&nbsp;"org.freedesktop.Secret.Item.Attributes": {<br>
     *                   &nbsp;&nbsp;&nbsp;&nbsp;"Attribute1": "Value1",<br>
     *                   &nbsp;&nbsp;&nbsp;&nbsp;"Attribute2": "Value2"<br>
     *                   &nbsp;&nbsp;}<br>
     *                   }<br>
     *                   </code></p>
     *
     *                   <p>
     *                   <b>Note:</b>
     *                   Please note that there is a distinction between the terms <i>Property</i>, which refers
     *                   to D-Bus properties of an object, and <i>Attribute</i>, which refers to one of a
     *                   secret item's string-valued attributes.
     *                   </p>
     * @param secret     The secret to store in the item, encoded with the included session.
     * @param replace    Whether to replace an item with the same attributes or not.
     * @return Pair&lt;item, prompt&gt;<br>
     * <br>
     * item                 &mdash; The item created, or the special value '/' if a prompt is necessary.<br>
     * <br>
     * prompt               &mdash; A prompt object, or the special value '/' if no prompt is necessary.<br>
     *
     * <br>
     * See Also:<br>
     * {@link de.swiesend.secretservice.Collection#createProperties(String label)}<br>
     * {@link de.swiesend.secretservice.Item#createProperties(String label, Map attributes)}<br>
     * @see Pair
     * @see ObjectPath
     * @see Secret
     * @see Item
     */
    Optional<Pair<ObjectPath, ObjectPath>> createItem(Map<String, Variant> properties, Secret secret, boolean replace);

    /**
     * <b>Items</b> is a D-Bus Property.
     *
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     *
     * @return Items in this collection.
     */
    Optional<List<ObjectPath>> getItems();

    /**
     * <b>Label</b> is a D-Bus Property.
     *
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     *
     * @return The displayable label of this collection.
     *
     * <p>
     * <b>Note:</b>
     * The displayable <code>label</code> can differ from the actual <code>name</code> of a collection.
     * </p>
     */
    Optional<String> getLabel();

    /**
     * <b>Label</b> is a D-Bus Property.
     *
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     *
     * @param label The displayable label of this collection.
     *
     *              <p>
     *              <b>Note:</b>
     *              The displayable <code>label</code> can differ from the actual <code>name</code> of a collection.
     *              </p>
     * @return
     */
    boolean setLabel(String label);

    /**
     * @return Whether the collection is locked and must be authenticated by the client application.
     */
    boolean isLocked();

    /**
     * @return The unix time when the collection was created.
     */
    Optional<UInt64> created();

    /**
     * @return The unix time when the collection was last modified.
     */
    Optional<UInt64> modified();

    class ItemCreated extends DBusSignal {
        public final DBusPath item;

        /**
         * A new item in this collection was created.
         *
         * @param path The path to the object this is emitted from.
         * @param item The item that was created.
         * @throws DBusException Could not communicate properly with the D-Bus.
         */
        public ItemCreated(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

    class ItemDeleted extends DBusSignal {
        public final DBusPath item;

        /**
         * An item in this collection was deleted.
         *
         * @param path The path to the object this is emitted from.
         * @param item The item that was deleted.
         * @throws DBusException Could not communicate properly with the D-Bus.
         */
        public ItemDeleted(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

    class ItemChanged extends DBusSignal {
        public final DBusPath item;

        /**
         * An item in this collection changed.
         *
         * @param path The path to the object this is emitted from.
         * @param item The item that was changed.
         * @throws DBusException Could not communicate properly with the D-Bus.
         */
        public ItemChanged(String path, DBusPath item) throws DBusException {
            super(path, item);
            this.item = item;
        }
    }

}
