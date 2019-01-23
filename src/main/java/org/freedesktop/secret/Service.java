package org.freedesktop.secret;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.types.Variant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Service extends org.freedesktop.secret.interfaces.Service {

    private Logger log = LoggerFactory.getLogger(getClass());
    private Session session = null;

    public static final List<Class> signals = Arrays.asList(
            CollectionCreated.class, CollectionChanged.class, CollectionDeleted.class);

    public Service(DBusConnection connection) {
        super(connection, signals,
                Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS,
                Static.Interfaces.SERVICE);
    }

    /**
     * Open a unique session for the caller application.
     *
     * @param algorithm The algorithm the caller wishes to use.
     * @param input     Input arguments for the algorithm.
     * @return Pair<output       ,               result>
     * output      Output of the session algorithm negotiation.
     * <p>
     * result      The object path of the session, if session was created.
     */
    @Override
    public Pair<Variant<byte[]>, ObjectPath> openSession(String algorithm, Variant input) {
        Object[] params = send("OpenSession", "sv", algorithm, input);
        session = new Session((ObjectPath) params[1], this);
        return new Pair(params[0], params[1]);
    }

    /**
     * @param properties Properties for the new collection. This allows setting the new collection's properties
     *                   upon its creation. All READWRITE properties are usable. Specify the property names in
     *                   full interface.Property form.<br>
     *                   <br>
     *                   Example for properties: <br>
     *                   <code>properties = { "org.freedesktop.Secret.Collection.Label": "MyCollection" }</code>
     *                   <br>
     * @param alias      If creating this connection for a well known alias then a string like default. If an
     *                   collection with this well-known alias already exists, then that collection will be returned
     *                   instead of creating a new collection. Any readwrite properties provided to this function
     *                   will be set on the collection.<br>
     *                   <br>
     *                   Set this to an empty string if the new collection should not be associated with a well known
     *                   alias.
     * @return Pair&lt;ObjectPath, ObjectPath&gt;<br>
     *
     * <p>collection &mdash; The new collection object, or '/' if prompting is necessary.</p>
     * <p>prompt     &mdash; A prompt object if prompting is necessary, or '/' if no prompt was needed.</p>
     * @see Pair
     */
    @Override
    public Pair<ObjectPath, ObjectPath> createCollection(Map<String, Variant> properties, String alias) {
        if (alias == null) {
            alias = "";
        }
        Object[] params = send("CreateCollection", "a{sv}s", properties, alias);
        return new Pair(params[0], params[1]);
    }

    public Pair<ObjectPath, ObjectPath> createCollection(Map<String, Variant> properties) {
        return createCollection(properties, null);
    }

    @Override
    public Pair<List<ObjectPath>, List<ObjectPath>> searchItems(Map<String, String> attributes) {
        Object[] params = send("SearchItems", "a{ss}", attributes);
        return new Pair(params[0], params[1]);
    }

    @Override
    public Pair<List<ObjectPath>, ObjectPath> unlock(List<ObjectPath> objects) {
        Object[] params = send("Unlock", "ao", objects);
        return new Pair(params[0], params[1]);
    }

    /**
     * Lock the items.
     *
     * @param objects Objects to lock.
     * @return Pair(locked, prompt)
     * <p>
     * locked      Objects that were locked without a prompt.
     * <p>
     * prompt      A prompt to lock the objects, or the special value '/' when no prompt is necessary.
     * @see Pair
     */
    @Override
    public Pair<List<ObjectPath>, ObjectPath> lock(List<ObjectPath> objects) {
        Object[] params = send("Lock", "ao", objects);
        return new Pair(params[0], params[1]);
    }

    @Override
    public void lockService() {
        send("LockService", "");
    }

    @Override
    public ObjectPath changeLock(ObjectPath collection) {
        Object[] params = send("ChangeLock", "o", collection);
        return (ObjectPath) params[0];
    }

    @Override
    public Map<ObjectPath, Secret> getSecrets(List<ObjectPath> items, DBusPath session) {
        Object[] params = send("GetSecrets", "aoo", items, session);
        return (Map<ObjectPath, Secret>) params[0];
    }

    @Override
    public ObjectPath readAlias(String name) {
        Object[] params = send("ReadAlias", "s", name);
        return (ObjectPath) params[0];
    }

    @Override
    public void setAlias(String name, ObjectPath collection) {
        send("SetAlias", "so", name, collection);
    }

    @Override
    public List<ObjectPath> getCollections() {
        Variant response = getProperty("Collections");
        return (ArrayList<ObjectPath>) response.getValue();
    }

    @Override
    public boolean isRemote() {
        return false;
    }

    @Override
    public String getObjectPath() {
        return Static.ObjectPaths.SECRETS;
    }

    public Session getSession() {
        return session;
    }

}
