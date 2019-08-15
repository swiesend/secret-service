package org.freedesktop.secret.simple;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Collection;
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
import java.util.*;

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
     *
     * @throws IOException  Could not communicate properly with the D-Bus. Check the logs.
     */
    public SimpleCollection() throws IOException {
        try {
            init();
            ObjectPath path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
            this.collection = new Collection(path, service);
            unlock();
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not initialize the default collection");
        }
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
     *
     * @throws IOException  Could not communicate properly with the D-Bus. Check the logs.
     *
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
                        Thread.sleep(100L);
                    } catch (InterruptedException e) {
                        log.error(e.toString(), e.getCause());
                    }
                    Service.CollectionCreated cc = service
                            .getSignalHandler()
                            .getLastHandledSignal(Service.CollectionCreated.class)
                            .orElseThrow(DBusException::new);
                    path = cc.collection;
                }

                this.collection = new Collection(path, service);
            }

            unlock();
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not initialize collection {label: " + label + "}");
        }
    }

    private void init() throws DBusException {
        try {
            encryption = new TransportEncryption();
            encryption.initialize();
            encryption.openSession();
            encryption.generateSessionKey();
            service = encryption.getService();
            session = service.getSession();
            prompt = new Prompt(service);
            withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(service);
        } catch (NoSuchAlgorithmException |
                InvalidAlgorithmParameterException |
                InvalidKeySpecException |
                InvalidKeyException e) {
            throw new DBusException(e.toString(), e.getCause());
        }
    }

    private Map<ObjectPath, String> getLabels() throws DBusException {
        List<ObjectPath> collections = service.getCollections();

        Map<ObjectPath, String> labels = new HashMap();
        for (ObjectPath path : collections) {
            Collection c = new Collection(path, service, null);
            labels.put(path, c.getLabel());
        }

        return labels;
    }

    private boolean exists(String label) throws DBusException {
        Map<ObjectPath, String> labels = getLabels();
        return labels.values().contains(label);
    }

    private ObjectPath getCollectionPath(String label) throws DBusException {
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

    private void performPrompt(ObjectPath path) throws DBusException {
        if (!("/".equals(path.getPath()))) {
            prompt.await(path);
        }
    }

    private void unlock() throws DBusException {
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

    private void getUserPermission() throws AccessControlException, DBusException {
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
    public void close() throws DBusException {
        clear();
        if (session != null) {
            session.close();
        }
    }

    /**
     * Delete this collection.
     *
     * @throws AccessControlException
     * @throws IOException
     */
    public void delete() throws AccessControlException, IOException {
        try {
            if (!isDefault()) {
                ObjectPath promptPath = collection.delete();
                performPrompt(promptPath);
            } else {
                throw new AccessControlException("The default collection may not be deleted with the simple API.");
            }
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not delete collection {path: " + collection.getObjectPath() + "}");
        }
    }

    /**
     * Creates an item with the provided properties in this collection.
     *
     * @param label      The displayable label of the new item
     * @param password   The password of the new item
     * @param attributes The attributes of the new item
     * @return an Optional with the DBus object path, otherwise an empty Optional
     * @throws IllegalArgumentException The label and password are non nullable.
     * @throws IOException
     */
    public Optional<String> createItem(String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException, IOException {

        if (password == null) {
            throw new IllegalArgumentException("The password may not be null.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The label of the password may not be null.");
        }

        try {
            unlock();

            DBusPath item = null;
            final Map<String, Variant> properties = Item.createProperties(label, attributes);
            try (final Secret secret = encryption.encrypt(password)) {
                Pair<ObjectPath, ObjectPath> response = collection.createItem(properties, secret, false);
                item = response.a;
                if ("/".equals(item.getPath())) {
                    Completed completed = prompt.await(response.b);
                    if (!completed.dismissed) {
                        Collection.ItemCreated ic = collection
                                .getSignalHandler()
                                .getLastHandledSignal(Collection.ItemCreated.class)
                                .orElseThrow(DBusException::new);
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

            if (item != null) {
                return Optional.of(item.getPath());
            } else {
                return Optional.empty();
            }
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not create item {label: " + label + "}");
        }
    }

    /**
     * Creates an item with the provided properties in this collection.
     *
     * @param label    The displayable label of the new item
     * @param password The password of the new item
     * @return an Optional with the DBus object path, otherwise an empty Optional
     * @throws IllegalArgumentException The label and password are non nullable.
     * @throws IOException
     */
    public Optional<String> createItem(String label, CharSequence password) throws IllegalArgumentException, IOException {
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
     * @throws IOException
     */
    public void updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException, IOException {

        if (objectPath == null) {
            throw new IllegalArgumentException("The object path of the item may not be null.");
        }

        try {
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
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not update item {path: " + objectPath + ", label: " + label + "}");
        }
    }

    /**
     * Get the displayable label of an item.
     *
     * @param objectPath The DBus object path of the item
     * @return label of the item
     * @throws IOException
     */
    public String getLabel(String objectPath) throws IOException {
        try {
            unlock();
            return getItem(objectPath).getLabel();
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not get the label of item {path: " + objectPath + "}");
        }
    }

    /**
     * Get the user specified attributes of an item.
     * <br>
     * <br>
     * <p><b>NOTE:</b> The attributes can contain an additional <code>xdg:schema</code> key-value pair.</p>
     *
     * @param objectPath The DBus object path of the item
     * @return on Optional with a <i>non-empty</i> map of item attributes, otherwise an empty Optional
     * @throws IOException
     */
    public Optional<Map<String, String>> getAttributes(String objectPath) throws IOException {
        try {
            unlock();
            Map<String, String> attributes = getItem(objectPath).getAttributes();
            if (attributes != null && !attributes.isEmpty())
                return Optional.of(attributes);
            else {
                return Optional.empty();
            }
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not get the attributes of item {path: " + objectPath + "}");
        }
    }

    /**
     * Get the object paths of items with given attributes.
     *
     * @param attributes The attributes of the items which are to be searched
     * @return an Optional with a <i>non-empty</i> list of object paths, otherwise an empty Optional
     * @throws IOException
     */
    public Optional<List<String>> getItems(Map<String, String> attributes) throws IOException {
        try {
            unlock();

            List<ObjectPath> objects = collection.searchItems(attributes);

            if (objects != null && !objects.isEmpty()) {
                return Optional.of(Static.Convert.toStrings(objects));
            } else {
                return Optional.empty();
            }
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not get the searched items {attributes: " + Arrays.toString(attributes.entrySet().toArray()) + "}");
        }
    }

    /**
     * Get the secret of the item.
     *
     * @param objectPath The DBus object path of the item
     * @return Optional plain chars
     */
    public char[] getSecret(String objectPath) throws IOException {
        try {
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

            if (decrypted != null) {
                return decrypted;
            } else {
                throw new IOException("Empty secret {path: " + objectPath + "}");
            }
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            throw new IOException("Could not get the secret {path: " + objectPath + "}");
        }
    }

    /**
     * Get the secrets from this collection.
     * <br>
     * <br>
     * <p><b>NOTE:</b> Retrieving all passwords form a collection requires user permission with a prompt.</p>
     *
     * @return Optional mapping of DBus object paths and plain chars
     */
    public Optional<Map<String, char[]>> getSecrets() throws AccessControlException, IOException {
        try {
            getUserPermission();

            List<ObjectPath> items = collection.getItems();

            Map<String, char[]> passwords = new HashMap();
            for (ObjectPath item : items) {
                String path = item.getPath();
                passwords.put(path, getSecret(path));
            }

            if (passwords.isEmpty()) {
                return Optional.empty();
            } else {
                return Optional.of(passwords);
            }
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
            return Optional.empty();
        }
    }

    /**
     * Delete an item from this collection.
     * <br>
     * <br>
     * <p><b>NOTE:</b> Deleting a password form a collection requires user permission with a prompt.</p>
     *
     * @param objectPath The DBus object path of the item
     * @throws AccessControlException
     * @throws IOException
     */
    public void deleteItem(String objectPath) throws AccessControlException, IOException {
        try {
            getUserPermission();

            Item item = getItem(objectPath);
            ObjectPath promptPath = item.delete();
            performPrompt(promptPath);
        } catch (DBusException e) {
            throw new IOException("Could not delete item (" + objectPath + ") : " + e.toString(), e.getCause());
        }
    }

    /**
     * Delete specified items from this collection.
     * <br>
     * <br>
     * <p><b>NOTE:</b> Deleting passwords form a collection requires user permission with a prompt.</p>
     *
     * @param objectPaths The DBus object paths of the items
     * @throws AccessControlException
     * @throws IOException
     */
    public void deleteItems(List<String> objectPaths) throws AccessControlException, IOException {
        for (String item : objectPaths) {
            deleteItem(item);
        }
    }
}
