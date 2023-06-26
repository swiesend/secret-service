package de.swiesend.secret.functional;

import de.swiesend.secret.functional.interfaces.CollectionInterface;
import de.swiesend.secret.functional.interfaces.ServiceInterface;
import de.swiesend.secret.functional.interfaces.SessionInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.*;
import org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;

import static org.freedesktop.secret.Static.DBus.DEFAULT_DELAY_MILLIS;

public class Collection implements CollectionInterface {

    private static final Logger log = LoggerFactory.getLogger(Collection.class);

    org.freedesktop.secret.Collection collection = null;
    SessionInterface session = null;
    ServiceInterface service = null;
    DBusConnection connection = null;
    private Duration timeout = null;
    private Boolean isUnlockedOnceWithUserPermission = false;
    private String label = null;
    private String id = null;
    private Optional<Secret> encryptedCollectionPassword = null;
    private Prompt prompt = null;
    private InternalUnsupportedGuiltRiddenInterface withoutPrompt = null;

    private ObjectPath path = null;

    public Collection(SessionInterface session) {
        init(session);

        this.path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        this.collection = new org.freedesktop.secret.Collection(path, connection);
        this.label = collection.getLabel().get();
        this.id = collection.getId();
    }

    public Collection(SessionInterface session, String label, Optional<CharSequence> maybePassword) {
        init(session);

        this.encryptedCollectionPassword = maybePassword
                .flatMap(password -> session.getEncryptedSession().encrypt(password));

        this.collection = getOrCreateCollection(label)
                .orElseThrow(() -> new NoSuchElementException(String.format("Cloud not acquire collection with name %s", label)));
        this.path = collection.getPath();
        this.label = label;
        this.id = collection.getId();
    }

    private void init(SessionInterface session) {
        this.session = session;
        this.service = session.getService();
        this.connection = service.getService().getConnection();
        this.timeout = session.getService().getTimeout();
        this.prompt = new Prompt(session.getService().getService());
        if (service.isOrgGnomeKeyringAvailable()) {
            this.withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(session.getService().getService());
        }
    }

    private Optional<org.freedesktop.secret.Collection> getOrCreateCollection(String label) {
        Optional<ObjectPath> maybePath;

        if (exists(label)) {
            maybePath = getCollectionPath(label);
        } else {
            maybePath = createNewCollection(label);
        }

        return maybePath.flatMap(path -> getCollectionFromPath(path, label));
    }

    private Optional<ObjectPath> createNewCollection(String label) {
        ObjectPath path = null;
        Map<String, Variant> properties = org.freedesktop.secret.Collection.createProperties(label);

        if (encryptedCollectionPassword.isEmpty()) {
            path = createCollectionWithPrompt(properties);
        } else if (service.isOrgGnomeKeyringAvailable()) {
            path = withoutPrompt.createWithMasterPassword(properties, encryptedCollectionPassword.get()).get();
        }

        if (path == null) {
            waitForCollectionCreatedSignal();
            Service.CollectionCreated signal = service.getService().getSignalHandler().getLastHandledSignal(Service.CollectionCreated.class);
            DBusPath signalPath = signal.collection;
            if (signalPath == null || signalPath.getPath() == null) {
                log.error(String.format("Received bad signal `CollectionCreated` without proper collection path: %s", signal));
                return null;
            }
            path = Static.Convert.toObjectPath(signalPath.getPath());
        }

        if (path == null) {
            log.error("Could not acquire a path for the prompt.");
            return null;
        }

        return Optional.ofNullable(path);
    }

    private void waitForCollectionCreatedSignal() {
        try {
            Thread.currentThread().sleep(DEFAULT_DELAY_MILLIS);
        } catch (InterruptedException e) {
            log.error("Unexpected interrupt while waiting for a CollectionCreated signal.", e);
        }
    }

    private ObjectPath createCollectionWithPrompt(Map<String, Variant> properties) {
        Pair<ObjectPath, ObjectPath> response = service.getService().createCollection(properties).get();
        if (!"/".equals(response.a.getPath())) {
            return response.a;
        }
        performPrompt(response.b);
        return null;
    }

    private Optional<org.freedesktop.secret.Collection> getCollectionFromPath(ObjectPath path, String label) {
        if (path == null) {
            log.error(String.format("Could not acquire collection with label: \"%s\"", label));
            return Optional.empty();
        }

        collection = new org.freedesktop.secret.Collection(path, connection);
        return Optional.of(collection);
    }

    private Optional<ObjectPath> getCollectionPath(String label) {
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
        return Optional.ofNullable(path);
    }

    private boolean isDefault() {
        if (connection != null && connection.isConnected()) {
            List<String> defaults = Arrays.asList(null, "login", "session", "default");
            return defaults.contains(collection.getId());
        } else {
            log.error("No D-Bus connection: Cannot check if the collection is the default collection.");
            return false;
        }
    }

    private void performPrompt(ObjectPath path) {
        if (!("/".equals(path.getPath()))) {
            prompt.await(path, timeout);
        }
    }


    @Override
    public boolean clear() {
        if (encryptedCollectionPassword.isPresent()) {
            encryptedCollectionPassword.get().clear();
            // TODO: remove log statement
            log.info("collection password: " + encryptedCollectionPassword.get().getSecretValue());
        }
        return true;
    }

    @Override
    public Optional<String> createItem(String label, CharSequence password) {
        return createItem(label, password, null);
    }

    @Override
    public Optional<String> createItem(String label, CharSequence password, Map<String, String> attributes) {
        if (Static.Utils.isNullOrEmpty(password)) {
            log.error("The password may not be null or empty.");
            return Optional.empty();
        }
        if (label == null) {
            log.error("The label of the item may not be null.");
            return Optional.empty();
        }

        if (collection == null || session.getEncryptedSession() == null) {
            log.error("Not collection or session");
            return Optional.empty();
        }

        unlock();

        Optional<String> result = session.getEncryptedSession().encrypt(password)
                .flatMap(secret -> {
                    try (secret) { // auto-close
                        final Map<String, Variant> properties = Item.createProperties(label, attributes);
                        return collection.createItem(properties, secret, false)
                                .flatMap(pair -> Optional.ofNullable(pair.a)
                                        .map(item -> {
                                            if ("/".equals(item.getPath())) { // prompt required
                                                org.freedesktop.secret.interfaces.Prompt.Completed completed = prompt.await(pair.b);
                                                if (completed.dismissed) {
                                                    return item;
                                                } else {
                                                    return collection
                                                            .getSignalHandler()
                                                            .getLastHandledSignal(org.freedesktop.secret.Collection.ItemCreated.class)
                                                            .item;
                                                }
                                            } else {
                                                return item;
                                            }
                                        })
                                        .map(DBusPath::getPath));
                    }
                });
        return result;
    }

    @Override
    public boolean delete() {
        if (!isDefault()) {
            ObjectPath promptPath = collection.delete().get();
            performPrompt(promptPath);
        } else {
            log.error("Default collections may not be deleted with the simple API.");
            return false;
        }
        return true;
    }

    @Override
    public boolean deleteItem(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) {
            log.error("Cannot delete an unspecified item.");
            return false;
        }

        unlockWithUserPermission();

        Item item = getItem(objectPath).get();
        ObjectPath promptPath = item.delete().get();
        performPrompt(promptPath);
        return true;
    }

    @Override
    public boolean deleteItems(List<String> objectPaths) {
        unlockWithUserPermission();

        boolean allDeleted = true;

        for (String item : objectPaths) {
            boolean success = deleteItem(item);
            if (!success) {
                allDeleted = false;
            }
        }

        return allDeleted;
    }

    @Override
    public Optional<Map<String, String>> getAttributes(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return null;
        unlock();
        return getItem(objectPath).flatMap(item -> item.getAttributes());
    }

    @Override
    public Optional<List<String>> getItems(Map<String, String> attributes) {
        if (attributes == null) return Optional.empty();
        unlock();

        return Optional.ofNullable(collection.searchItems(attributes))
                .filter(objects -> !objects.isEmpty())
                .flatMap(objects -> objects.map(Static.Convert::toStrings));
    }

    @Override
    public Optional<String> getItemLabel(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return Optional.empty();
        unlock();
        return getItem(objectPath)
                .flatMap(item -> item.getLabel());
    }

    @Override
    public boolean setItemLabel(String objectPath, String label) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return false;
        unlock();
        return getItem(objectPath)
                .map(item -> item.setLabel(label))
                .orElse(false);
    }

    @Override
    public boolean setLabel(String label) {
        boolean success = collection.setLabel(label);
        if (success) {
            this.label = label;
        }
        return success;
    }

    @Override
    public Optional<String> getLabel() {
        return Optional.of(this.label);
    }

    @Override
    public Optional<String> getId() {
        return Optional.of(this.collection.getId());
    }

    @Override
    public Optional<char[]> getSecret(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return Optional.empty();
        unlock();

        return getItem(objectPath)
                .flatMap(item -> {
                    ObjectPath sessionPath = session.getSession().getPath();
                    return item.getSecret(sessionPath);
                })
                .flatMap(secret -> {
                    try {
                        char[] decrypted = session.getEncryptedSession().decrypt(secret);
                        return Optional.of(decrypted);
                    } catch (BadPaddingException |
                             IllegalBlockSizeException |
                             InvalidAlgorithmParameterException |
                             InvalidKeyException |
                             NoSuchAlgorithmException |
                             NoSuchPaddingException e) {
                        log.error("Could not decrypt the secret.", e);
                        return Optional.empty();
                    } finally {
                        secret.clear();
                    }
                });
    }

    @Override
    public Optional<Map<String, char[]>> getSecrets() {
        unlockWithUserPermission();

        List<ObjectPath> items = collection.getItems().get();
        if (items == null) return null;

        Map<String, char[]> passwords = new HashMap();
        for (ObjectPath item : items) {
            String path = item.getPath();
            passwords.put(path, getSecret(path).get());
        }

        return Optional.of(passwords);
    }

    @Override
    public boolean isLocked() {
        if (connection != null && connection.isConnected()) {
            return collection.isLocked();
        } else {
            log.error("No D-Bus connection: Cannot check if the collection is locked.");
            return true;
        }
    }

    @Override
    public boolean lock() {
        if (collection != null && !collection.isLocked()) {
            service.getService().lock(lockable());
            log.info("Locked collection: \"" + collection.getLabel().get() + "\" (" + collection.getObjectPath() + ")");
            try {
                Thread.currentThread().sleep(DEFAULT_DELAY_MILLIS);
            } catch (InterruptedException e) {
                log.error("Unexpected interrupt while waiting for a collection to lock.", e);
            }
        }
        return collection.isLocked();
    }

    private void unlock() {
        if (collection != null && collection.isLocked()) {
            if (encryptedCollectionPassword.isEmpty() || isDefault()) {
                Pair<List<ObjectPath>, ObjectPath> response = service.getService().unlock(lockable()).get();
                performPrompt(response.b);
                if (!collection.isLocked()) {
                    isUnlockedOnceWithUserPermission = true;
                    log.info("Unlocked collection: \"" + collection.getLabel().get() + "\" (" + collection.getObjectPath() + ")");
                }
            } else if (encryptedCollectionPassword.isPresent() && service.isOrgGnomeKeyringAvailable()) {
                withoutPrompt.unlockWithMasterPassword(collection.getPath(), encryptedCollectionPassword.get());
                log.debug("Unlocked collection: \"" + collection.getLabel().get() + "\" (" + collection.getObjectPath() + ")");
            }
        }
    }

    @Override
    public boolean unlockWithUserPermission() {
        if (!isUnlockedOnceWithUserPermission && isDefault()) lock();
        unlock();
        if (collection.isLocked()) {
            log.error("The collection was not unlocked with user permission.");
            return false;
        }
        return true;
    }

    @Override
    public boolean updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) {

        if (Static.Utils.isNullOrEmpty(objectPath)) {
            log.error("The object path of the item may not be null or empty.");
            return false;
        }

        if (Static.Utils.isNullOrEmpty(password)) {
            log.error("The password may not be null or empty.");
            return false;
        }

        unlock();

        Item item = getItem(objectPath).get();

        if (label != null) {
            item.setLabel(label);
        }

        if (attributes != null) {
            item.setAttributes(attributes);
        }

        return session.getEncryptedSession().encrypt(password)
                .map(secret -> {
                    try (secret) { // auto-close
                        return item.setSecret(secret); // side-effect
                    }
                })
                .orElse(false);
    }

    @Override
    public void close() throws Exception {
        if (encryptedCollectionPassword.isPresent()) {
            encryptedCollectionPassword.get().close();
            log.trace("cleared collection password");
        }
        log.trace("closed collection");
    }

    private Map<ObjectPath, String> getLabels() {
        List<ObjectPath> collections = service.getService().getCollections().get();

        Map<ObjectPath, String> labels = new HashMap();
        for (ObjectPath path : collections) {
            org.freedesktop.secret.Collection c = new org.freedesktop.secret.Collection(path, connection, null);
            labels.put(path, c.getLabel().get());
        }

        return labels;
    }

    private boolean exists(String label) {
        Map<ObjectPath, String> labels = getLabels();
        return labels.containsValue(label);
    }

    private Optional<Item> getItem(String path) {
        if (path != null) {
            return Optional.of(new Item(Static.Convert.toObjectPath(path), service.getService()));
        } else {
            return Optional.empty();
        }
    }

    private List<ObjectPath> lockable() {
        return Arrays.asList(collection.getPath());
    }
}