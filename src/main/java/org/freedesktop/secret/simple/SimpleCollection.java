package org.freedesktop.secret.simple;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Collection;
import org.freedesktop.secret.*;
import org.freedesktop.secret.errors.NoSuchObject;
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
import org.freedesktop.secret.interfaces.Prompt.Completed;

public final class SimpleCollection {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollection.class);

    private TransportEncryption encryption = null;
    private Service service = null;
    private Session session = null;
    private Prompt prompt = null;
    private InternalUnsupportedGuiltRiddenInterface withoutPrompt = null;

    private Collection collection;
    private List<ObjectPath> unlock = null;
    private String password = null;

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
     * @param label     The label of the collection.
     *
     *                  NOTE: The 'label' of a collection may differ from the 'id' of a collection, which get assigned
     *                  by the Secret Service.
     *
     *                  A SimpleCollection can't handle collections with the same label, but different ids correctly.
     */
    public SimpleCollection(String label, String password) {
        init();

        if (exists(label)) {
            ObjectPath path = getCollectionPath(label);
            this.collection = new Collection(path, service);
        } else {
            Map<String, Variant> properties = Collection.createProperties(label);
            DBusPath path = null;

            if (password == null) {
                Pair<ObjectPath, ObjectPath> response = service.createCollection(properties);
                if (!response.a.getPath().equals("/")) {
                    path = response.a;
                }
                performPrompt(response.b);
            } else {
                Secret encrypted = null;
                try {
                    encrypted = encryption.encrypt(password);
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                    log.error(e.toString(), e.getCause());
                }
                path = withoutPrompt.createWithMasterPassword(properties, encrypted);
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

        this.password = password;
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
        } catch (DBusException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeySpecException | InvalidKeyException e) {
            log.error(e.toString(), e.getCause());
        }
    }

    private Map<ObjectPath, String> getLabels() {
        List<ObjectPath> collections = service.getCollections();

        Map<ObjectPath, String> labels = new HashMap();
        for (ObjectPath path: collections) {
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
        for (Map.Entry<ObjectPath, String> entry: labels.entrySet()) {
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
        if (unlock == null) {
            unlock = Arrays.asList(collection.getPath());
        }
        log.info("locked: " + collection.isLocked());
        if (collection.isLocked()) {
            if (password == null) {
                Pair<List<ObjectPath>, ObjectPath> response = service.unlock(unlock);
                performPrompt(response.b);
            } else {
                Secret encrypted = null;
                try {
                    encrypted = encryption.encrypt(password);
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                    log.error(e.toString(), e.getCause());
                }
                withoutPrompt.unlockWithMasterPassword(collection.getPath(), encrypted);
            }
        }
    }

    private Item pathToItem(DBusPath path) {
        return new Item(Static.Convert.toObjectPath(path.getPath()), service);
    }

    private void getUserPermission() {
        if(isDefault()) {
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

    public DBusPath createPassword(String label, String password, Map<String, String> attributes) throws IllegalArgumentException {

        if (password == null) {
            throw new IllegalArgumentException("The password may not be null.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The label of the password may not be null.");
        }

        DBusPath item = null;
        try {
            unlock();
            Map<String, Variant> properties = Item.createProperties(label, attributes);
            Secret secret = encryption.encrypt(password);
            Pair<ObjectPath, ObjectPath> response = collection.createItem(properties, secret, false);
            performPrompt(response.b);
            item = response.a;
            if ("/".equals(item.getPath())) {
                Completed completed = prompt.getLastHandledSignal();
                if (!completed.dismissed) {
                    Collection.ItemCreated ic = (Collection.ItemCreated) collection.getSignalHandler().getLastHandledSignal();
                    item = ic.item;
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException  e) {
            log.error(e.toString(), e.getCause());
        }

        return item;
    }

    public DBusPath createPassword(String label, String password) throws IllegalArgumentException {
        return createPassword(label, password, null);
    }

    public void updatePassword(DBusPath object, String label, String password, Map<String, String> attributes) throws IllegalArgumentException {

        if (object == null) {
            throw new IllegalArgumentException("The object path of the item may not be null.");
        }
        if (password == null) {
            throw new IllegalArgumentException("The new password may not be null.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The new label of the item may not be null.");
        }

        try {
            unlock();
            Item item = pathToItem(object);
            item.setLabel(label);
            if (attributes == null) {
                item.setAttributes(Collections.emptyMap());
            } else {
                item.setAttributes(attributes);
            }
            Secret secret = encryption.encrypt(password);
            item.setSecret(secret);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            log.error(e.toString(), e.getCause());
        }
    }

    public Item getItem(DBusPath object) {
        unlock();
        return pathToItem(object);
    }

    public String getPassword(DBusPath object) {
        unlock();
        Item item = pathToItem(object);
        Secret secret = item.getSecret(session.getPath());
        String decrypted = null;
        try {
            decrypted = encryption.decrypt(secret);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            log.error(e.toString(), e.getCause());
        }
        return decrypted;
    }

    public Map<DBusPath, String> getPasswords() {
        getUserPermission();

        List<ObjectPath> items = collection.getItems();
        Map<DBusPath, String> passwords = new HashMap();
        for (ObjectPath item : items) {
            passwords.put(item, getPassword(item));
        }
        return passwords;
    }

    public void deletePassword(DBusPath object) {
        getUserPermission();

        Item item = pathToItem(object);
        ObjectPath promptPath = item.delete();
        performPrompt(promptPath);
    }

    public void deletePasswords(List<DBusPath> objects) {
        for (DBusPath item : objects) {
            deletePassword(item);
        }
    }

}
