package org.freedesktop.secret.simple;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.*;
import org.freedesktop.secret.interfaces.Prompt.Completed;
import org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.AccessControlException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class SimpleCollection implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollection.class);
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(120);
    private TransportEncryption encryption = null;
    private Service service = null;
    private Session session = null;
    private Prompt prompt = null;
    private InternalUnsupportedGuiltRiddenInterface withoutPrompt = null;
    private Collection collection;
    private Secret encrypted = null;
    private Duration timeout = DEFAULT_TIMEOUT;

    /**
     * The default collection.
     *
     * @throws IOException Could not communicate properly with the D-Bus. Check the logs.
     */
    public SimpleCollection() throws IOException {
        try {
            init();

            ObjectPath path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
            this.collection = new Collection(path, service);
            unlock();
            if (this.collection.isLocked())
                throw new IOException("Could not communicate properly with the secret-service.");
        } catch (RuntimeException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException(e.toString(), e.getCause());
        }
    }

    /**
     * A user specified collection.
     *
     * @param label    The displayable label of the collection
     *
     *                 <p>
     *                 NOTE: The 'label' of a collection may differ from the 'id' of a collection. The 'id' is
     *                 assigned by the Secret Service and used in the DBus object path of a collection or item.
     *                 </p>
     *
     *                 A SimpleCollection can't handle collections with the same label, but different ids correctly.
     * @param password Password of the collection
     * @throws IOException Could not communicate properly with the D-Bus. Check the logs.
     */
    public SimpleCollection(String label, CharSequence password) throws IOException {
        try {
            init();

            if (exists(label)) {
                ObjectPath path = getCollectionPath(label);
                this.collection = new Collection(path, service);
            } else {
                DBusPath path = null;
                Map<String, Variant> properties = Collection.createProperties(label);

                if (password == null) {
                    Pair<ObjectPath, ObjectPath> response = service.createCollection(properties);
                    if (!"/".equals(response.a.getPath())) {
                        path = response.a;
                    }
                    performPrompt(response.b);
                } else {
                    try {
                        encrypted = encryption.encrypt(password);
                        path = withoutPrompt.createWithMasterPassword(properties, encrypted);
                    } catch (NoSuchAlgorithmException |
                            NoSuchPaddingException |
                            InvalidAlgorithmParameterException |
                            InvalidKeyException |
                            BadPaddingException |
                            IllegalBlockSizeException e) {
                        log.error(e.toString(), e.getCause());
                    }
                }

                if (path == null) {
                    try {
                        Thread.currentThread().sleep(100L);
                    } catch (InterruptedException e) {
                        log.error(e.toString(), e.getCause());
                    }
                    Service.CollectionCreated cc = service.getSignalHandler().getLastHandledSignal(Service.CollectionCreated.class);
                    path = cc.collection;
                }

                if (path == null) throw new IOException("Could not communicate properly with the secret-service.");

                this.collection = new Collection(path, service);
            }

            unlock();
            if (this.collection.isLocked())
                throw new IOException("Could not communicate properly with the secret-service.");
        } catch (RuntimeException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException(e.toString(), e.getCause());
        }
    }

    private void init() throws IOException {
        try {
            encryption = new TransportEncryption();
            encryption.initialize();
            encryption.openSession();
            encryption.generateSessionKey();
            service = encryption.getService();
            session = service.getSession();
            prompt = new Prompt(service);
            withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(service);
        } catch (DBusException |
                NoSuchAlgorithmException |
                InvalidAlgorithmParameterException |
                InvalidKeySpecException |
                InvalidKeyException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException(e.toString(), e.getCause());
        }
    }

    private Map<ObjectPath, String> getLabels() {
        List<ObjectPath> collections = service.getCollections();

        Map<ObjectPath, String> labels = new HashMap();
        for (ObjectPath path : collections) {
            Collection c = new Collection(path, service, null);
            labels.put(path, c.getLabel());
        }

        return labels;
    }

    private boolean exists(String label) {
        Map<ObjectPath, String> labels = getLabels();
        return labels.containsValue(label);
    }

    private ObjectPath getCollectionPath(String label) {
        Map<ObjectPath, String> labels = getLabels();

        ObjectPath path = null;
        for (Map.Entry<ObjectPath, String> entry : labels.entrySet()) {
            ObjectPath p = entry.getKey();
            String l = entry.getValue();
            if (label.equals(l)) {
                path = p;
                break;
            }
        }
        return path;
    }

    private boolean isDefault() {
        List<String> defaults = Arrays.asList(null, "login", "session", "default");
        return defaults.contains(collection.getId());
    }

    private void performPrompt(ObjectPath path) {
        if (!("/".equals(path.getPath()))) {
            prompt.await(path, timeout);
        }
    }

    private Item getItem(String path) {
        return new Item(Static.Convert.toObjectPath(path), service);
    }

    void lock() {
        if (collection != null && !collection.isLocked()) {
            List<ObjectPath> lockable = Arrays.asList(collection.getPath());
            service.lock(lockable);
            try {
                Thread.currentThread().sleep(250L);
            } catch (InterruptedException e) {
                log.error(e.toString(), e.getCause());
            }
        }
    }

    private void unlock() {
        if (collection != null && collection.isLocked()) {
            if (encrypted == null) {
                Pair<List<ObjectPath>, ObjectPath> response = service.unlock(Arrays.asList(collection.getPath()));
                performPrompt(response.b);
            } else {
                withoutPrompt.unlockWithMasterPassword(collection.getPath(), encrypted);
            }
        }
    }

    void unlockWithUserPermission() throws AccessControlException {
        if (isDefault()) {
            List<ObjectPath> lockable = Arrays.asList(collection.getPath());
            service.lock(lockable);
            try {
                Thread.currentThread().sleep(250L);
            } catch (InterruptedException e) {
                log.error(e.toString(), e.getCause());
            }
            Pair<List<ObjectPath>, ObjectPath> response = service.unlock(lockable);
            performPrompt(response.b);
            if (collection.isLocked()) {
                throw new AccessControlException(
                        "One may not read passwords from the default collection without user permission."
                );
            }
        }
    }

    /**
     * Clears the private key of the transport encryption and the passphrase of the collection.
     */
    public void clear() {
        if (encryption != null) {
            encryption.clear();
        }
        if (encrypted != null) {
            encrypted.clear();
        }
    }

    @Override
    public void close() {
        clear();
        if (session != null) {
            session.close();
        }
    }

    /**
     * Delete this collection.
     */
    public void delete() throws AccessControlException {
        if (!isDefault()) {
            ObjectPath promptPath = collection.delete();
            performPrompt(promptPath);
        } else {
            throw new AccessControlException("Default collections may not be deleted with the simple API.");
        }
    }

    /**
     * Creates an item with the provided properties in this collection.
     *
     * @param label      The displayable label of the new item
     * @param password   The password of the new item
     * @param attributes The attributes of the new item
     * @return DBus object path or null
     * @throws IllegalArgumentException The label and password are non nullable.
     */
    public String createItem(String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException {

        if (password == null) {
            throw new IllegalArgumentException("The password may not be null.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The label of the password may not be null.");
        }

        if (collection == null || encryption == null) return null;

        unlock();

        DBusPath item = null;
        final Map<String, Variant> properties = Item.createProperties(label, attributes);
        try (final Secret secret = encryption.encrypt(password)) {
            Pair<ObjectPath, ObjectPath> response = collection.createItem(properties, secret, false);
            item = response.a;
            if ("/".equals(item.getPath())) {
                Completed completed = prompt.await(response.b);
                if (!completed.dismissed) {
                    Collection.ItemCreated ic = collection.getSignalHandler().getLastHandledSignal(Collection.ItemCreated.class);
                    item = ic.item;
                }
            }
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException |
                InvalidAlgorithmParameterException |
                InvalidKeyException |
                BadPaddingException |
                IllegalBlockSizeException e) {
            log.error(e.toString(), e.getCause());
        }

        if (null != item) {
            return item.getPath();
        } else {
            return null;
        }
    }

    /**
     * Creates an item with the provided properties in this collection.
     *
     * @param label    The displayable label of the new item
     * @param password The password of the new item
     * @return DBus object path
     * @throws IllegalArgumentException The label and password are non nullable.
     */
    public String createItem(String label, CharSequence password) throws IllegalArgumentException {
        return createItem(label, password, null);
    }

    /**
     * Updates an item with the provided properties.
     *
     * @param objectPath The DBus object path of the item
     * @param label      The displayable label of the new item
     * @param password   The password of the new item
     * @param attributes The attributes of the new item
     * @throws IllegalArgumentException The object path, label and password are non nullable.
     */
    public void updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException {

        if (objectPath == null) {
            throw new IllegalArgumentException("The object path of the item may not be null.");
        }

        unlock();

        Item item = getItem(objectPath);

        if (label != null) {
            item.setLabel(label);
        }

        if (attributes != null) {
            item.setAttributes(attributes);
        }

        if (password != null) try (Secret secret = encryption.encrypt(password)) {
            item.setSecret(secret);
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException |
                InvalidAlgorithmParameterException |
                InvalidKeyException |
                BadPaddingException |
                IllegalBlockSizeException e) {
            log.error(e.toString(), e.getCause());
        }
    }

    /**
     * Get the displayable label of an item.
     *
     * @param objectPath The DBus object path of the item
     * @return label
     */
    public String getLabel(String objectPath) {
        if (objectPath == null) return null;
        unlock();
        return getItem(objectPath).getLabel();
    }

    /**
     * Get the user specified attributes of an item.
     * <p>
     * NOTE: <p>The attributes can contain an additional 'xdg:schema' key-value pair.</p>
     *
     * @param objectPath The DBus object path of the item
     * @return item attributes
     */
    public Map<String, String> getAttributes(String objectPath) {
        if (objectPath == null) return null;
        unlock();
        return getItem(objectPath).getAttributes();
    }

    /**
     * Get the object paths of items with given attributes.
     *
     * @param attributes The attributes of the secret
     * @return object paths
     */
    public List<String> getItems(Map<String, String> attributes) {
        if (attributes == null) return null;
        unlock();

        List<ObjectPath> objects = collection.searchItems(attributes);

        if (objects != null && !objects.isEmpty()) {
            return Static.Convert.toStrings(objects);
        } else {
            return null;
        }
    }

    /**
     * Get the secret of the item.
     *
     * @param objectPath The DBus object path of the item
     * @return plain chars
     */
    public char[] getSecret(String objectPath) {
        if (objectPath == null) return null;
        unlock();

        final Item item = getItem(objectPath);

        char[] decrypted = null;
        try (final Secret secret = item.getSecret(session.getPath())) {
            decrypted = encryption.decrypt(secret);
        } catch (NoSuchPaddingException |
                NoSuchAlgorithmException |
                InvalidAlgorithmParameterException |
                InvalidKeyException |
                BadPaddingException |
                IllegalBlockSizeException e) {
            log.error(e.toString(), e.getCause());
        }
        return decrypted;
    }

    /**
     * Get the secrets from this collection.
     * <p>
     * NOTE: <p>Retrieving all passwords form a collection requires user permission.</p>
     *
     * @return Mapping of DBus object paths and plain chars
     */
    public Map<String, char[]> getSecrets() throws AccessControlException {
        unlockWithUserPermission();

        List<ObjectPath> items = collection.getItems();
        if (items == null) return null;

        Map<String, char[]> passwords = new HashMap();
        for (ObjectPath item : items) {
            String path = item.getPath();
            passwords.put(path, getSecret(path));
        }

        return passwords;
    }

    /**
     * Delete an item from this collection.
     * <p>
     * NOTE: <p>Deleting a password form a collection requires user permission.</p>
     *
     * @param objectPath The DBus object path of the item
     */
    public void deleteItem(String objectPath) throws AccessControlException {
        unlockWithUserPermission();

        Item item = getItem(objectPath);
        ObjectPath promptPath = item.delete();
        performPrompt(promptPath);
    }

    /**
     * Delete specified items from this collection.
     * <p>
     * NOTE: <p>Deleting passwords form a collection requires user permission.</p>
     *
     * @param objectPaths The DBus object paths of the items
     */
    public void deleteItems(List<String> objectPaths) throws AccessControlException {
        for (String item : objectPaths) {
            deleteItem(item);
        }
    }

    public Duration getTimeout() {
        return timeout;
    }

    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
    }

}
