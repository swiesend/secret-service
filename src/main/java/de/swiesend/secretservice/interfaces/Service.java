package de.swiesend.secretservice.interfaces;

import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.freedesktop.dbus.DBusPath;
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
         * A collection was deleted.
         * @param collection    Collection that was deleted.
        public CollectionDeleted(String path, DBusPath collection) throws DBusException {
    class CollectionChanged extends DBusSignal {
         * A collection was changed.
         * @param collection    Collection that was changed.
        public CollectionChanged(String path, DBusPath collection) throws DBusException {
    /**
     * Open a unique session for the caller application.
     *
     * @param algorithm The algorithm the caller wishes to use.
     * @param input     Input arguments for the algorithm.
     * @return Pair&lt;output, result&gt;<br>
     * <br>
     * output   &mdash; Output of the session algorithm negotiation.<br>
     * result   &mdash; The object path of the session, if session was created.<br>
     * 
     * @see Pair
     * @see Variant
     * @see DBusPath
     */
    Optional<Pair<Variant<byte[]>, DBusPath>> openSession(String algorithm, Variant input);
     * Create a new collection with the specified properties.
     * @param properties Properties for the new collection. This allows setting the new collection's properties
     *                   upon its creation. All READWRITE properties are usable. Specify the property names in
     *                   full interface.Property form.<br>
     *                   <br>
     *                   Example for properties:
     *                   <p>
     *                      <code>properties = { "org.freedesktop.Secret.Collection.Label": "MyCollection" }</code>
     *                   </p>
     * @param alias      If creating this connection for a well known alias then a string like <code>"default"</code>.
     *                   If an collection with this well-known alias already exists, then that collection will be
     *                   returned instead of creating a new collection. Any readwrite properties provided to this
     *                   function will be set on the collection.<br>
     *                   Set this to an <i>empty string</i> if the new collection should not be associated with a well
     *                   known alias.
     * @return Pair&lt;collection, prompt&gt;<br>
     * collection   &mdash; The new collection object, or '/' if prompting is necessary.<br>
     * prompt       &mdash; A prompt object if prompting is necessary, or '/' if no prompt was needed.<br>
    Optional<Pair<DBusPath, DBusPath>> createCollection(Map<String, Variant> properties, String alias);
    Optional<Pair<DBusPath, DBusPath>> createCollection(Map<String, Variant> properties);
     * Find items in any collection.
     * @param attributes    Find secrets in any collection.
     *                      <p>
     *                          <b>Example:</b>
     *                          <code>{
     *                              "Attribute1": "Value1",
     *                              "Attribute2": "Value2"
     *                          }</code>
     *                      </p>
     *                          <b>Note:</b>
     *                          Please note that there is a distinction between the terms <i>Property</i>, which refers
     *                          to D-Bus properties of an object, and <i>Attribute</i>, which refers to one of a
     *                          secret item's string-valued attributes.
     * @return Pair&lt;unlocked, locked&gt;<br>
     * unlocked      &mdash; Items found.<br>
     * locked        &mdash; Items found that require authentication.<br>
    Optional<Pair<List<DBusPath>, List<DBusPath>>> searchItems(Map<String, String> attributes);
     * Unlock the specified objects.
     * @param objects  Objects to unlock.
     * @return Pair&lt;unlocked, prompt&gt;<br>
     * unlocked     &mdash; Objects that were unlocked without a prompt.<br>
     * prompt       &mdash; A prompt object which can be used to unlock the remaining objects, or the special value '/' when no prompt is necessary.<br>
    Optional<Pair<List<DBusPath>, DBusPath>> unlock(List<DBusPath> objects);
     * Lock the items.
     * @param objects Objects to lock.
     * @return Pair&lt;locked, prompt&gt;<br>
     * locked      &mdash; Objects that were locked without a prompt.<br>
     * prompt      &mdash; A prompt to lock the objects, or the special value '/' when no prompt is necessary.<br>
    Optional<Pair<List<DBusPath>, DBusPath>> lock(List<DBusPath> objects);
     * Lock the entire Secret Service API.
     * See Also:<br>
     * {@link #lock(List objects)}<br>
     * {@link #unlock(List objects)}<br>
     * {@link InternalUnsupportedGuiltRiddenInterface#unlockWithMasterPassword(DBusPath collection, Secret master)}<br>
    boolean lockService();
     * Toggle the lock for a collection with a prompt.
     * @param collection    Path of the collection.
     * @return Path of the collection
     * {@link InternalUnsupportedGuiltRiddenInterface#changeWithPrompt(DBusPath collection)}<br>
    Optional<DBusPath> changeLock(DBusPath collection);
     * Retrieve multiple secrets from different items.
     * @param items        Items to get secrets for.
     * @param session      The session to use to encode the secrets.
     * @return secrets     &mdash; Secrets for the items.
     * @see Secret
    Optional<Map<DBusPath, Secret>> getSecrets(List<DBusPath> items, DBusPath session);
     * Get the collection with the given alias.
     * @param name          An alias, such as 'default'.
     * @return collection   &mdash; The collection or the the path '/' if no such collection exists.
     * @see Static.ObjectPaths
     * @see Collection
    Optional<DBusPath> readAlias(String name);
     * Setup a collection alias.
     * @param collection    The collection to make the alias point to. To remove an alias use the special value '/'.
    boolean setAlias(String name, DBusPath collection);
     * @return A list of present collections.
    Optional<List<DBusPath>> getCollections();
}
