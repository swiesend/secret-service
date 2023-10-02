package de.swiesend.secretservice.interfaces;

import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.Pair;
import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.Static;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@DBusInterfaceName(Static.Interfaces.SERVICE)
public interface Service extends DBusInterface {

    class CollectionCreated extends DBusSignal {
        public final DBusPath collection;

        /**
         * A collection was created.
         *
         * @param path          The path to the object this is emitted from.
         *
         * @param collection    Collection that was created.
         * 
         * @throws DBusException Could not communicate properly with the D-Bus.
         */
        public CollectionCreated(String path, DBusPath collection) throws DBusException {
            super(path, collection);
            this.collection = collection;
        }
    }

    class CollectionDeleted extends DBusSignal {
        public final DBusPath collection;

        /**
         * A collection was deleted.
         *
         * @param path          The path to the object this is emitted from.
         *
         * @param collection    Collection that was deleted.
         *
         * @throws DBusException Could not communicate properly with the D-Bus.
         */
        public CollectionDeleted(String path, DBusPath collection) throws DBusException {
            super(path, collection);
            this.collection = collection;
        }
    }

    class CollectionChanged extends DBusSignal {
        public final DBusPath collection;

        /**
         * A collection was changed.
         *
         * @param path          The path to the object this is emitted from.
         *
         * @param collection    Collection that was changed.
         *
         * @throws DBusException Could not communicate properly with the D-Bus.
         */
        public CollectionChanged(String path, DBusPath collection) throws DBusException {
            super(path, collection);
            this.collection = collection;
        }
    }

    /**
     * Open a unique session for the caller application.
     *
     * @param algorithm The algorithm the caller wishes to use.
     * @param input     Input arguments for the algorithm.
     *
     * @return Pair&lt;output, result&gt;<br>
     * <br>
     * output   &mdash; Output of the session algorithm negotiation.<br>
     * <br>
     * result   &mdash; The object path of the session, if session was created.<br>
     * 
     * @see Pair
     * @see Variant
     * @see ObjectPath
     */
    Optional<Pair<Variant<byte[]>, ObjectPath>> openSession(String algorithm, Variant input);

    /**
     * Create a new collection with the specified properties.
     * 
     * @param properties Properties for the new collection. This allows setting the new collection's properties
     *                   upon its creation. All READWRITE properties are usable. Specify the property names in
     *                   full interface.Property form.<br>
     *                   <br>
     *                   Example for properties:
     *                   <p>
     *                      <code>properties = { "org.freedesktop.Secret.Collection.Label": "MyCollection" }</code>
     *                   </p>
     *
     * @param alias      If creating this connection for a well known alias then a string like <code>"default"</code>.
     *                   If an collection with this well-known alias already exists, then that collection will be
     *                   returned instead of creating a new collection. Any readwrite properties provided to this
     *                   function will be set on the collection.<br>
     *                   <br>
     *                   Set this to an <i>empty string</i> if the new collection should not be associated with a well
     *                   known alias.
     *
     * @return Pair&lt;collection, prompt&gt;<br>
     * <br>
     * collection   &mdash; The new collection object, or '/' if prompting is necessary.<br>
     * <br>
     * prompt       &mdash; A prompt object if prompting is necessary, or '/' if no prompt was needed.<br>
     * 
     * @see Pair
     * @see Variant
     * @see ObjectPath
     */
    Optional<Pair<ObjectPath, ObjectPath>> createCollection(Map<String, Variant> properties, String alias);

    /**
     * Create a new collection with the specified properties.
     * 
     * @param properties Properties for the new collection. This allows setting the new collection's properties
     *                   upon its creation. All READWRITE properties are usable. Specify the property names in
     *                   full interface.Property form.<br>
     *                   <br>
     *                   Example for properties:
     *                   <p>
     *                      <code>properties = { "org.freedesktop.Secret.Collection.Label": "MyCollection" }</code>
     *                   </p>
     *
     * @return Pair&lt;collection, prompt&gt;<br>
     * <br>
     * collection   &mdash; The new collection object, or '/' if prompting is necessary.<br>
     * <br>
     * prompt       &mdash; A prompt object if prompting is necessary, or '/' if no prompt was needed.<br>
     * 
     * @see Pair
     * @see Variant
     * @see ObjectPath
     */
    Optional<Pair<ObjectPath, ObjectPath>> createCollection(Map<String, Variant> properties);

    /**
     * Find items in any collection.
     * 
     * @param attributes    Find secrets in any collection.
     *
     *                      <p>
     *                          <b>Example:</b>
     *                          <code>{
     *                              "Attribute1": "Value1",
     *                              "Attribute2": "Value2"
     *                          }</code>
     *                      </p>
     *
     *                      <p>
     *                          <b>Note:</b>
     *                          Please note that there is a distinction between the terms <i>Property</i>, which refers
     *                          to D-Bus properties of an object, and <i>Attribute</i>, which refers to one of a
     *                          secret item's string-valued attributes.
     *                      </p>
     *
     * @return Pair&lt;unlocked, locked&gt;<br>
     * <br>
     * unlocked      &mdash; Items found.<br>
     * <br>
     * locked        &mdash; Items found that require authentication.<br>
     * 
     * @see Pair
     * @see ObjectPath
     */
    Optional<Pair<List<ObjectPath>, List<ObjectPath>>> searchItems(Map<String, String> attributes);

    /**
     * Unlock the specified objects.
     * 
     * @param objects  Objects to unlock.
     *
     * @return Pair&lt;unlocked, prompt&gt;<br>
     * <br>
     * unlocked     &mdash; Objects that were unlocked without a prompt.<br>
     * <br>
     * prompt       &mdash; A prompt object which can be used to unlock the remaining objects, or the special value '/' when no prompt is necessary.<br>
     * 
     * @see Pair
     * @see ObjectPath
     */
    Optional<Pair<List<ObjectPath>, ObjectPath>> unlock(List<ObjectPath> objects);

    /**
     * Lock the items.
     *
     * @param objects Objects to lock.
     *
     * @return Pair&lt;locked, prompt&gt;<br>
     * <br>
     * locked      &mdash; Objects that were locked without a prompt.<br>
     * <br>
     * prompt      &mdash; A prompt to lock the objects, or the special value '/' when no prompt is necessary.<br>
     * 
     * @see Pair
     */
    Optional<Pair<List<ObjectPath>, ObjectPath>> lock(List<ObjectPath> objects);

    /**
     * Lock the entire Secret Service API.
     *
     * <br>
     * See Also:<br>
     * {@link #lock(List objects)}<br>
     * {@link #unlock(List objects)}<br>
     * {@link InternalUnsupportedGuiltRiddenInterface#unlockWithMasterPassword(DBusPath collection, Secret master)}<br>
     */
    boolean lockService();

    /**
     * Toggle the lock for a collection with a prompt.
     *
     * @param collection    Path of the collection.
     *
     * @return Path of the collection
     * 
     * <br>
     * See Also:<br>
     * {@link InternalUnsupportedGuiltRiddenInterface#changeWithPrompt(DBusPath collection)}<br>
     */
    Optional<ObjectPath> changeLock(ObjectPath collection);

    /**
     * Retrieve multiple secrets from different items.
     * 
     * @param items        Items to get secrets for.
     *
     * @param session      The session to use to encode the secrets.
     *
     * @return secrets     &mdash; Secrets for the items.
     * 
     * @see Secret
     * @see ObjectPath
     */
    Optional<Map<ObjectPath, Secret>> getSecrets(List<ObjectPath> items, ObjectPath session);

    /**
     * Get the collection with the given alias.
     * 
     * @param name          An alias, such as 'default'.
     *
     * @return collection   &mdash; The collection or the the path '/' if no such collection exists.
     * 
     * @see Static.ObjectPaths
     * @see ObjectPath
     * @see Collection
     */
    Optional<ObjectPath> readAlias(String name);

    /**
     * Setup a collection alias.

     * @param name          An alias, such as 'default'.
     *
     * @param collection    The collection to make the alias point to. To remove an alias use the special value '/'.
     *
     * @see ObjectPath
     * @see Collection
     */
    boolean setAlias(String name, ObjectPath collection);

    /**
     * @return A list of present collections.
     */
    Optional<List<ObjectPath>> getCollections();

}
