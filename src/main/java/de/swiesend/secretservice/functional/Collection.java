package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.*;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.types.Variant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;

import static de.swiesend.secretservice.Static.DBus.DEFAULT_DELAY_MILLIS;

/**
 * Representation of a Secret-Service collection. Main interface to interact with the keyring. Guarantees a valid Secret-Service session.
 */
public class Collection implements CollectionInterface {

    private static final Logger log = LoggerFactory.getLogger(Collection.class);

    de.swiesend.secretservice.Collection collection = null;
    SessionInterface session = null;
    ServiceInterface service = null;
    DBusConnection connection = null;
    private Duration timeout = null;
    private Boolean isUnlockedOnceWithUserPermission = false;
    private Optional<String> label = Optional.empty();
    private String id = null;
    private Optional<Secret> encryptedCollectionPassword = Optional.empty();
    private Prompt prompt = null;
    private InternalUnsupportedGuiltRiddenInterface withoutPrompt = null;

    private ObjectPath path = null;

    public Collection(SessionInterface session) {
        init(session);

        this.path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        this.collection = new de.swiesend.secretservice.Collection(path, connection);
        this.label = collection.getLabel();
        this.id = collection.getId();
    }

    public Collection(SessionInterface session, String label, Optional<CharSequence> maybePassword) {
        init(session);

        this.encryptedCollectionPassword = maybePassword
                .flatMap(password -> session.getEncryptedSession().encrypt(password));

        // TODO: the constructor may not throw an error...
        this.collection = getOrCreateCollection(label)
                .orElseThrow(() -> new NoSuchElementException(
                        String.format("Could not acquire collection with name %s", label)
                ));
        this.path = collection.getPath();
        this.label = Optional.ofNullable(label);
        this.id = collection.getId();
    }

    private void init(SessionInterface session) {
        this.session = session;
        this.service = session.getService();
        this.connection = service.getService().getConnection();
        this.timeout = session.getService().getTimeout();
        this.prompt = new Prompt(session.getService().getService());
        if (service.isGnomeKeyringAvailable()) {
            this.withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(session.getService().getService());
        }
    }

    private Optional<de.swiesend.secretservice.Collection> getOrCreateCollection(String label) {
        Optional<ObjectPath> maybePath = getCollectionPath(label);

        if (maybePath.isEmpty()) {
            maybePath = createNewCollection(label);
        }

        return maybePath.flatMap(path -> getCollectionFromPath(path, label));
    }

    private Optional<ObjectPath> createNewCollection(String label) {
        ObjectPath path = null;
        Map<String, Variant> properties = de.swiesend.secretservice.Collection.createProperties(label);

        if (encryptedCollectionPassword.isEmpty()) {
            Optional<ObjectPath> maybePath = createCollectionWithPrompt(properties);
            if (maybePath.isPresent()) {
                path = maybePath.get();
            } else {
                return Optional.empty();
            }
        } else if (service.isGnomeKeyringAvailable()) {
            path = withoutPrompt.createWithMasterPassword(properties, encryptedCollectionPassword.get()).get();
        }

        if (path == null) {
            waitForCollectionCreatedSignal();
            Service.CollectionCreated signal = service.getService().getSignalHandler().getLastHandledSignal(Service.CollectionCreated.class);
            if (signal == null) {
                log.warn("Collection \"" + label + "\" was not created.");
                return Optional.empty();
            }

            DBusPath signalPath = signal.collection;
            if (signalPath == null || signalPath.getPath() == null) {
                log.error(String.format("Received bad signal `CollectionCreated` without proper collection path: %s", signal));
                return Optional.empty();
            }
            path = Static.Convert.toObjectPath(signalPath.getPath());
        }

        if (path == null) {
            log.error("Could not acquire a path for the prompt.");
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

    private Optional<ObjectPath> createCollectionWithPrompt(Map<String, Variant> properties) {
        Pair<ObjectPath, ObjectPath> response = service.getService().createCollection(properties).get();
        if (!"/".equals(response.a.getPath())) {
            return Optional.of(response.a);
        } else {
            return performPrompt(response.b);
        }
    }

    private Optional<de.swiesend.secretservice.Collection> getCollectionFromPath(ObjectPath path, String label) {
        if (path == null) {
            log.error(String.format("Could not acquire collection with label: \"%s\"", label));
            return Optional.empty();
        }

        collection = new de.swiesend.secretservice.Collection(path, connection);
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

    private Optional<ObjectPath> performPrompt(ObjectPath path) {
        if (!("/".equals(path.getPath()))) {
            return Optional.ofNullable(prompt.await(path, timeout))
                    .filter(completed -> !completed.dismissed)
                    .map(success -> new ObjectPath(success.getSource(), success.result.getValue().toString()));
        } else {
            return Optional.empty();
        }
    }

    @Override
    public boolean clear() {
        if (encryptedCollectionPassword.isPresent()) {
            encryptedCollectionPassword.get().clear();
        }
        return true;
    }

    @Override
    public Optional<String> createItem(String label, CharSequence secret) {
        return createItem(label, secret, null);
    }

    @Override
    public Optional<String> createItem(String label, CharSequence secret, Map<String, String> attributes) {
        if (Static.Utils.isNullOrEmpty(secret)) {
            log.error("The secret may not be null or empty.");
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

        Optional<String> result = session
                .getEncryptedSession()
                .encrypt(secret)
                .flatMap(secInst -> {
                    try (secInst) { // auto-close
                        final Map<String, Variant> properties = Item.createProperties(label, attributes);
                        return collection
                                .createItem(properties, secInst, false)
                                .flatMap(pair -> Optional.ofNullable(pair.a)
                                        .map(item -> {
                                            if ("/".equals(item.getPath())) { // prompt required
                                                de.swiesend.secretservice.interfaces.Prompt.Completed completed = prompt.await(pair.b);
                                                if (completed.dismissed) {
                                                    return item;
                                                } else {
                                                    return collection
                                                            .getSignalHandler()
                                                            .getLastHandledSignal(de.swiesend.secretservice.Collection.ItemCreated.class)
                                                            .item;
                                                }
                                            } else {
                                                return item;
                                            }
                                        })
                                        .map(DBusPath::getPath)
                                );
                    }
                });
        return result;
    }

    @Override
    public boolean delete() {
        if (isDefault()) {
            log.error("The default collection shall only be deleted with the low-level API.");
            return false;
        }

        return collection.delete()
                .map(promptPath -> promptPath.getPath().equals("/") || performPrompt(promptPath).isPresent())
                .orElse(false);
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
        Optional<ObjectPath> performedPrompt = performPrompt(promptPath);
        if (service.isGnomeKeyringAvailable() && performedPrompt.isEmpty()) {
            // gnome-keyring returns no path;
            return true;
        } else {
            // KeePassXC returns an empty path
            return performedPrompt.isPresent();
        }
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
            this.label = Optional.ofNullable(label);
        }
        return success;
    }

    @Override
    public Optional<String> getLabel() {
        return this.label;
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
                    Optional<char[]> decrypted = session.getEncryptedSession().decrypt(secret); // TODO: should this be final?
                    secret.clear();
                    return decrypted;
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

    private boolean unlock() {
        if (collection != null && collection.isLocked()) {
            if (encryptedCollectionPassword.isEmpty() || isDefault()) {
                Optional<Pair<List<ObjectPath>, ObjectPath>> maybeResponse = service.getService().unlock(lockable());
                if (maybeResponse.isPresent()) {
                    ObjectPath promptPath = maybeResponse.get().b;
                    if (performPrompt(promptPath).isPresent() && !collection.isLocked()) {
                        isUnlockedOnceWithUserPermission = true;
                        log.debug("Unlocked collection: \"" + collection.getLabel().get() + "\" (" + collection.getObjectPath() + ")");
                        return true;
                    }
                }
            } else if (encryptedCollectionPassword.isPresent() && service.isGnomeKeyringAvailable()) {
                boolean result = withoutPrompt.unlockWithMasterPassword(collection.getPath(), encryptedCollectionPassword.get());
                if (result == true) {
                    log.debug("Unlocked collection: \"" + collection.getLabel().get() + "\" (" + collection.getObjectPath() + ")");
                }
                return result;
            }
        }
        log.debug("Could not unlocked collection: \"" + collection.getLabel().get() + "\" (" + collection.getObjectPath() + ")");
        return false;
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
            de.swiesend.secretservice.Collection c = new de.swiesend.secretservice.Collection(path, connection, null);
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
