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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class SimpleCollection implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollection.class);

    private TransportEncryption encryption = null;
    private Service service = null;
    private Session session = null;
    private Prompt prompt = null;
    private InternalUnsupportedGuiltRiddenInterface withoutPrompt = null;

    private Collection collection;
    private Secret encrypted = null;

    /**
     * The default collection.
     */
    public SimpleCollection() throws IOException {
        init();
        ObjectPath path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        this.collection = new Collection(path, service);
        unlock();
    }

    /**
     * A user specified collection.
     *
     * @param label     The displayable label of the collection
     *
     *                  <p>
     *                      NOTE: The 'label' of a collection may differ from the 'id' of a collection. The 'id' is
     *                      assigned by the Secret Service and used in the DBus object path of a collection or item.
     *                  <p>
     *
     *                  A SimpleCollection can't handle collections with the same label, but different ids correctly.
     *
     * @param password  Password of the collection
     */
    public SimpleCollection(String label, CharSequence password) throws IOException {
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
                    Thread.sleep(100L);
                } catch (InterruptedException e) {
                    log.error(e.toString(), e.getCause());
                }
                Service.CollectionCreated cc = service.getSignalHandler().getLastHandledSignal(Service.CollectionCreated.class);
                path = cc.collection;
            }

            this.collection = new Collection(path, service);
        }

        unlock();
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
        return labels.values().contains(label);
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

    private final boolean isDefault() {
        List<String> defaults = Arrays.asList(null, "login", "session", "default");
        return defaults.contains(collection.getId());
    }

    private void performPrompt(ObjectPath path) {
        if (!("/".equals(path.getPath()))) {
            prompt.await(path);
        }
    }

    private void unlock() {
        if (collection.isLocked()) {
            if (encrypted == null) {
                Pair<List<ObjectPath>, ObjectPath> response = service.unlock(Arrays.asList(collection.getPath()));
                performPrompt(response.b);
            } else {
                withoutPrompt.unlockWithMasterPassword(collection.getPath(), encrypted);
            }
        }
    }

    private Item getItem(String path) {
        return new Item(Static.Convert.toObjectPath(path), service);
    }

    private void getUserPermission() throws AccessControlException {
        if (isDefault()) {
            List<ObjectPath> lockable = Arrays.asList(collection.getPath());
            service.lock(lockable);
            try {
                Thread.sleep(250L);
            } catch (InterruptedException e) {
                log.error(e.toString(), e.getCause());
            }
            Pair<List<ObjectPath>, ObjectPath> response = service.unlock(lockable);
            performPrompt(response.b);
            if (collection.isLocked()) {
                throw new AccessControlException("One may not read all passwords from a default collection without permission.");
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
     * @param label         The displayable label of the new item
     * @param password      The password of the new item
     * @param attributes    The attributes of the new item
     *
     * @return DBus object path
     *
     * @throws IllegalArgumentException
     */
    public String createItem(String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException {

        if (password == null) {
            throw new IllegalArgumentException("The password may not be null.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The label of the password may not be null.");
        }

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

        return item.getPath();
    }

    /**
     * Creates an item with the provided properties in this collection.
     *
     * @param label         The displayable label of the new item
     * @param password      The password of the new item
     *
     * @return DBus object path
     *
     * @throws IllegalArgumentException
     */
    public String createItem(String label, CharSequence password) throws IllegalArgumentException {
        return createItem(label, password, null);
    }

    /**
     * Updates an item with the provided properties.
     *
     * @param objectPath    The DBus object path of the item
     * @param label         The displayable label of the new item
     * @param password      The password of the new item
     * @param attributes    The attributes of the new item
     *
     * @throws IllegalArgumentException
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
     * @param objectPath    The DBus object path of the item
     *
     * @return label
     */
    public String getLabel(String objectPath) {
        unlock();
        return getItem(objectPath).getLabel();
    }

    /**
     * Get the user specified attributes of an item.
     *
     * NOTE: <p>The attributes can contain an additional 'xdg:schema' key-value pair.</p>
     *
     * @param objectPath    The DBus object path of the item
     *
     * @return item attributes
     */
    public Map<String, String> getAttributes(String objectPath) {
        unlock();
        return getItem(objectPath).getAttributes();
    }

    /**
     * Get the object paths of items with given attributes.
     *
     * @return object paths
     */
    public List<String> getItems(Map<String, String> attributes) {
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
     * @param objectPath    The DBus object path of the item
     *
     * @return plain chars
     */
    public char[] getSecret(String objectPath) {
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
     *
     * NOTE: <p>Retrieving all passwords form a collection requires user permission.</p>
     *
     * @return Mapping of DBus object paths and plain chars
     */
    public Map<String, char[]> getSecrets() throws AccessControlException {
        getUserPermission();

        List<ObjectPath> items = collection.getItems();

        Map<String, char[]> passwords = new HashMap();
        for (ObjectPath item : items) {
            String path = item.getPath();
            passwords.put(path, getSecret(path));
        }

        return passwords;
    }

    /**
     * Delete an item from this collection.
     *
     * NOTE: <p>Deleting a password form a collection requires user permission.</p>
     *
     * @param objectPath    The DBus object path of the item
     */
    public void deleteItem(String objectPath) throws AccessControlException {
        getUserPermission();

        Item item = getItem(objectPath);
        ObjectPath promptPath = item.delete();
        performPrompt(promptPath);
    }

    /**
     * Delete specified items from this collection.
     *
     * NOTE: <p>Deleting passwords form a collection requires user permission.</p>
     *
     * @param objectPaths   The DBus object paths of the items
     */
    public void deleteItems(List<String> objectPaths) throws AccessControlException {
        for (String item : objectPaths) {
            deleteItem(item);
        }
    }
}
