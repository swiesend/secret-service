package org.freedesktop.secret.simple;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Collection;
import org.freedesktop.secret.*;
import org.freedesktop.secret.errors.NoSuchObject;
import org.freedesktop.secret.interfaces.Prompt.Completed;
import org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.AccessControlException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public final class SimpleCollection {

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
    public SimpleCollection() {
        init();
        ObjectPath path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        this.collection = new Collection(path, service);
        log.info("locked on creation:" + collection.isLocked());
        unlock();
    }

    /**
     * A user specified collection.
     *
     * @param label     The label of the collection
     *
     *                  <p>
     *                      NOTE: The 'label' of a collection may differ from the 'id' of a collection. The 'id' is
     *                      assigned by the Secret Service.
     *                  <p>
     *
     *                  A SimpleCollection can't handle collections with the same label, but different ids correctly.
     *
     * @param password Password of the collection
     */
    public SimpleCollection(String label, CharSequence password) {
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
                Service.CollectionCreated cc = (Service.CollectionCreated) service.getSignalHandler().getLastHandledSignal();
                path = cc.collection;
            }

            this.collection = new Collection(path, service);
        }

        unlock();
    }

    private void init() {
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
            if (l.equals(label)) {
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
            try {
                prompt.await(path);
            } catch (InterruptedException | NoSuchObject e) {
                log.error(e.toString(), e.getCause());
            }
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

    private void getUserPermission() {
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
     * clear the passphrase of the collection.
     */
    public void clear() {
        if (encrypted != null) {
            encrypted.clear();
        }
    }

    /**
     * Delete this collection.
     */
    public void delete() throws AccessControlException {
        clear();

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
    public String createPassword(String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException {

        if (password == null) {
            throw new IllegalArgumentException("The password may not be null.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The label of the password may not be null.");
        }

        DBusPath item = null;
        try {
            unlock();
            final Map<String, Variant> properties = Item.createProperties(label, attributes);
            final Secret secret = encryption.encrypt(password);
            final Pair<ObjectPath, ObjectPath> response = collection.createItem(properties, secret, false);
            performPrompt(response.b);
            item = response.a;
            if ("/".equals(item.getPath())) {
                Completed completed = prompt.getLastHandledSignal();
                if (!completed.dismissed) {
                    Collection.ItemCreated ic = (Collection.ItemCreated) collection.getSignalHandler().getLastHandledSignal();
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
    public String createPassword(String label, CharSequence password) throws IllegalArgumentException {
        return createPassword(label, password, null);
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
    public void updatePassword(String objectPath, String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException {

        if (objectPath == null) {
            throw new IllegalArgumentException("The object path of the item may not be null.");
        }
        if (password == null) {
            throw new IllegalArgumentException("The new password may not be null.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The new label of the item may not be null.");
        }

        Secret secret = null;
        try {
            unlock();
            Item item = getItem(objectPath);
            item.setLabel(label);
            if (attributes == null) {
                item.setAttributes(Collections.emptyMap());
            } else {
                item.setAttributes(attributes);
            }
            secret = encryption.encrypt(password);
            item.setSecret(secret);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            log.error(e.toString(), e.getCause());
        } finally {
            if (secret != null) {
                secret.clear();
            }
        }
    }

    /**
     * Get the displayable label of an item.
     *
     * @param objectPath    The DBus object path of the item
     *
     * @return
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
     * Get the secret of the item.
     *
     * @param objectPath    The DBus object path of the item
     *
     * @return plain chars
     */
    public char[] getPassword(String objectPath) {
        unlock();
        final Item item = getItem(objectPath);
        final Secret secret = item.getSecret(session.getPath());
        char[] decrypted = null;
        try {
            decrypted = encryption.decrypt(secret);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            log.error(e.toString(), e.getCause());
        } finally {
            secret.clear();
        }
        return decrypted;
    }

    /**
     * Get the secrets from this collection.
     *
     * NOTE: <p>Retrieving all passwords form a collection requires permission.</p>
     *
     * @return Mapping of DBus object paths and plain chars
     */
    public Map<String, char[]> getPasswords() {
        getUserPermission();

        List<ObjectPath> items = collection.getItems();
        Map<String, char[]> passwords = new HashMap();
        for (ObjectPath item : items) {
            passwords.put(item.getPath(), getPassword(item.getPath()));
        }
        return passwords;
    }

    /**
     * Delete an item from this collection.
     *
     * NOTE: <p>Deleting passwords form a collection requires permission.</p>
     *
     * @param objectPath    The DBus object path of the item
     */
    public void deletePassword(String objectPath) {
        getUserPermission();

        Item item = getItem(objectPath);
        ObjectPath promptPath = item.delete();
        performPrompt(promptPath);
    }

    /**
     * Delete specified items from this collection.
     *
     * NOTE: <p>Deleting passwords form a collection requires permission.</p>
     *
     * @param objectPaths   The DBus object paths of the items
     */
    public void deletePasswords(List<String> objectPaths) {
        for (String item : objectPaths) {
            deletePassword(item);
        }
    }
}
