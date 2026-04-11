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
import java.util.function.Function;

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
    private Boolean isUnlockedOnceWithUserPermission = false;
    private Optional<String> label = Optional.empty();
    private String id = null;
    private Optional<Secret> encryptedCollectionPassword = Optional.empty();
    private Prompt prompt = null;
    private InternalUnsupportedGuiltRiddenInterface withoutPrompt = null;

    private ObjectPath path = null;

    private boolean clearSessionAtClose = false;

    private boolean isPrompting = true;

    private boolean isClosed = false;

    private Collection() {
    }

    /**
     * Open the default collection, creating a new session automatically.
     *
     * @return the default collection, or empty if the service is unavailable
     */
    public static Optional<CollectionInterface> openDefault() {
        return openDefault(Optional.empty());
    }

    /**
     * Open the default collection with an optional existing session.
     *
     * @param maybeSession an existing session to reuse, or empty to create a new one
     * @return the default collection, or empty if the service is unavailable
     */
    public static Optional<CollectionInterface> openDefault(Optional<SessionInterface> maybeSession) {
        Objects.requireNonNull(maybeSession, "maybeSession must not be null; use Optional.empty() instead");
        Collection c = new Collection();
        if (maybeSession.isEmpty()) {
            c.clearSessionAtClose = true;
        }
        if (!c.init(maybeSession)) {
            return Optional.empty();
        }
        c.path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        c.collection = new de.swiesend.secretservice.Collection(c.path, c.connection);
        c.label = c.collection.getLabel();
        c.id = c.collection.getId();
        return Optional.of(c);
    }

    /**
     * Open or create a named collection, creating a new session automatically.
     *
     * @param label the collection label
     * @return the collection, or empty if it could not be acquired
     */
    public static Optional<CollectionInterface> open(String label) {
        return open(label, Optional.empty(), Optional.empty());
    }

    /**
     * Open or create a named collection with an optional password.
     *
     * @param label         the collection label
     * @param maybePassword optional collection password
     * @return the collection, or empty if it could not be acquired
     */
    public static Optional<CollectionInterface> open(String label, Optional<CharSequence> maybePassword) {
        return open(label, maybePassword, Optional.empty());
    }

    /**
     * Open or create a named collection with an optional password and session.
     *
     * @param label         the collection label
     * @param maybePassword optional collection password
     * @param maybeSession  an existing session to reuse, or empty to create a new one
     * @return the collection, or empty if it could not be acquired
     */
    public static Optional<CollectionInterface> open(String label, Optional<CharSequence> maybePassword, Optional<SessionInterface> maybeSession) {
        if (label == null || label.isBlank()) {
            throw new IllegalArgumentException("The collection label must not be null or blank.");
        }
        Objects.requireNonNull(maybePassword, "maybePassword must not be null; use Optional.empty() instead");
        Objects.requireNonNull(maybeSession, "maybeSession must not be null; use Optional.empty() instead");
        Collection c = new Collection();
        if (maybeSession.isEmpty()) {
            c.clearSessionAtClose = true;
        }
        if (!c.init(maybeSession)) {
            return Optional.empty();
        }
        c.encryptedCollectionPassword = maybePassword.flatMap(
                password -> c.session.getEncryptedSession().encrypt(password)
        );

        Optional<de.swiesend.secretservice.Collection> maybeCollection = c.getOrCreateCollection(label);
        if (maybeCollection.isEmpty()) {
            log.warn("Could not acquire collection with name {}", label);
            return Optional.empty();
        }
        c.collection = maybeCollection.get();
        c.path = c.collection.getPath();
        c.label = Optional.ofNullable(label);
        c.id = c.collection.getId();
        return Optional.of(c);
    }

    private boolean init(Optional<SessionInterface> maybeSession) {
        if (maybeSession.isEmpty()) {
            this.clearSessionAtClose = true;
        }
        Optional<SessionInterface> resolved;
        if (maybeSession.isPresent()) {
            resolved = maybeSession;
        } else {
            Optional<ServiceInterface> maybeService = SecretService.create();
            if (maybeService.isEmpty()) {
                log.error("Could not create the secret service.");
                return false;
            }
            ServiceInterface createdService = maybeService.get();
            resolved = createdService.openSession();
            if (resolved.isEmpty()) {
                log.error("Could not open a session.");
                try {
                    createdService.close();
                } catch (Exception e) {
                    log.warn("Failed to close service after session failure.", e);
                }
                return false;
            }
        }
        this.session = resolved.get();
        this.service = session.getService();
        this.connection = service.getService().getConnection();
        this.prompt = new Prompt(session.getService().getService());
        if (service.isGnomeKeyringAvailable()) {
            this.withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(session.getService().getService());
        }
        return true;
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
            Optional<ObjectPath> maybePath = withoutPrompt.createWithMasterPassword(properties, encryptedCollectionPassword.get());
            if (maybePath.isPresent()) {
                path = maybePath.get();
            }
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
            Thread.sleep(DEFAULT_DELAY_MILLIS);
        } catch (InterruptedException e) {
            log.error("Unexpected interrupt while waiting for a CollectionCreated signal.", e);
        }
    }

    private Optional<ObjectPath> createCollectionWithPrompt(Map<String, Variant> properties) {
        Optional<Pair<ObjectPath, ObjectPath>> maybeResponse = service.getService().createCollection(properties);
        if (maybeResponse.isEmpty()) {
            log.error("Could not create collection.");
            return Optional.empty();
        }
        Pair<ObjectPath, ObjectPath> response = maybeResponse.get();
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
        if (!isPrompting) {
            log.trace("dismissed the prompt");
            return Optional.empty();
        }
        if (!("/".equals(path.getPath()))) {
            return Optional.ofNullable(prompt.await(path, service.getTimeout()))
                    .filter(completed -> !completed.dismissed)
                    .map(success -> new ObjectPath(success.getSource(), success.result.getValue().toString()));
        } else {
            return Optional.empty();
        }
    }

    @Override
    public boolean clear() {
        if (encryptedCollectionPassword.isPresent()) {
            boolean cleared = encryptedCollectionPassword.get().clear();
            encryptedCollectionPassword = Optional.empty();
            if (cleared) {
                log.trace("cleared collection password");
            } else {
                log.trace("Could not clear collection password");
            }
            return cleared;
        } else {
            log.trace("No collection password to clear");
            return true;
        }
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

        Optional<Item> maybeItem = getItem(objectPath);
        if (maybeItem.isEmpty()) {
            log.error("Item not found: {}", objectPath);
            return false;
        }
        Item item = maybeItem.get();

        Optional<ObjectPath> maybePromptPath = item.delete();
        if (maybePromptPath.isEmpty()) {
            log.error("Could not delete item: {}", objectPath);
            return false;
        }
        ObjectPath promptPath = maybePromptPath.get();
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
        if (objectPaths == null || objectPaths.isEmpty()) {
            log.error("Cannot delete unspecified items.");
            return false;
        }
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
        if (Static.Utils.isNullOrEmpty(objectPath)) return Optional.empty();
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
        if (label == null) {
            log.error("The label may not be null.");
            return false;
        }
        unlock();
        return getItem(objectPath)
                .map(item -> item.setLabel(label))
                .orElse(false);
    }

    @Override
    public boolean setLabel(String label) {
        if (label == null) {
            log.error("The label may not be null.");
            return false;
        }
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
    public boolean lockItem(String itemPath) {
        if (Static.Utils.isNullOrEmpty(itemPath)) {
            log.error("Cannot lock an unspecified item.");
            return false;
        }
        Item item = new Item(Static.Convert.toObjectPath(itemPath), service.getService());
        if (!item.isLocked()) {
            Optional<Pair<List<ObjectPath>, ObjectPath>> maybeLock = service.getService().lock(List.of(item.getPath()));
            if (maybeLock.isEmpty()) {
                log.error("Could not lock item: {}", itemPath);
                return false;
            }
            Pair<List<ObjectPath>, ObjectPath> lock = maybeLock.get();
            log.debug("lock item: {}", lock);
            de.swiesend.secretservice.interfaces.Prompt.Completed result = prompt.await(lock.b, service.getTimeout());
            log.debug("lock item prompt: {}", result);
        }
        return true;
    }

    @Override
    public boolean unlockItem(String itemPath) {
        if (Static.Utils.isNullOrEmpty(itemPath)) {
            log.error("Cannot unlock an unspecified item.");
            return false;
        }
        Item item = new Item(Static.Convert.toObjectPath(itemPath), service.getService());
        if (item.isLocked()) {
            service.getService().unlock(List.of(item.getPath())).ifPresent(unlock -> {
                log.debug("unlock item: {}", unlock);
                if(unlock.a.isEmpty()){
                    de.swiesend.secretservice.interfaces.Prompt.Completed await = prompt.await(unlock.b, service.getTimeout());
                    log.info(String.format("Unlocked Item: %s", await.result.getValue()));
                }
            });
        }
        return true;
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
                    try (secret) {
                        return session.getEncryptedSession().decrypt(secret);
                    }
                });
    }

    @Override
    public <R> Optional<R> withSecret(String objectPath, Function<char[], R> callback) {
        Objects.requireNonNull(callback, "callback must not be null");
        Optional<char[]> maybeSecret = getSecret(objectPath);
        if (maybeSecret.isEmpty()) {
            return Optional.empty();
        }
        char[] secret = maybeSecret.get();
        try {
            return Optional.ofNullable(callback.apply(secret));
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    @Override
    public Optional<Map<String, char[]>> getSecrets() {
        if (!unlockWithUserPermission()) {
            return Optional.empty();
        }

        Optional<List<ObjectPath>> maybeItems = collection.getItems();
        if (maybeItems.isEmpty()) return Optional.empty();

        List<ObjectPath> items = maybeItems.get();

        Map<String, char[]> passwords = new HashMap<>();
        for (ObjectPath item : items) {
            String path = item.getPath();
            getSecret(path).ifPresent(secret -> passwords.put(path, secret));
        }

        return Optional.of(passwords);
    }

    @Override
    public <R> Optional<R> withSecrets(Function<Map<String, char[]>, R> callback) {
        Objects.requireNonNull(callback, "callback must not be null");
        Optional<Map<String, char[]>> maybeSecrets = getSecrets();
        if (maybeSecrets.isEmpty()) {
            return Optional.empty();
        }
        Map<String, char[]> secrets = maybeSecrets.get();
        try {
            return Optional.ofNullable(callback.apply(secrets));
        } finally {
            for (char[] value : secrets.values()) {
                Arrays.fill(value, '\0');
            }
        }
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
            log.info("Locked collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
            try {
                Thread.sleep(DEFAULT_DELAY_MILLIS);
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
                        log.debug("Unlocked collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
                        return true;
                    }
                }
            } else if (encryptedCollectionPassword.isPresent() && service.isGnomeKeyringAvailable()) {
                boolean result = withoutPrompt.unlockWithMasterPassword(collection.getPath(), encryptedCollectionPassword.get());
                if (result == true) {
                    log.debug("Unlocked collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
                }
                return result;
            }
        }
        log.debug("Could not unlocked collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
        return false;
    }

    @Override
    public boolean unlockWithUserPermission() {
        // Lock before unlocking to force a user prompt, preventing silent access by malicious apps.
        // Applies to all collections (not just default) as the safer policy (CVE-2018-19358).
        if (!isUnlockedOnceWithUserPermission) lock();
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

        Optional<Item> maybeItem = getItem(objectPath);
        if (maybeItem.isEmpty()) {
            log.error("Item not found: {}", objectPath);
            return false;
        }
        Item item = maybeItem.get();

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
        if (!isClosed) {
            clear();
            if (clearSessionAtClose) {
                // Close the service (which cascades to registered sessions and the
                // underlying SystemInterface/D-Bus connection). Closing only the session
                // would leak the D-Bus connection created internally by init().
                service.close();
            }
        }
        log.trace("closed collection");
        isClosed = true;
    }

    private Map<ObjectPath, String> getLabels() {
        Optional<List<ObjectPath>> maybeCollections = service.getService().getCollections();
        if (maybeCollections.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<ObjectPath, String> labels = new HashMap<>();
        for (ObjectPath path : maybeCollections.get()) {
            de.swiesend.secretservice.Collection c = new de.swiesend.secretservice.Collection(path, connection, null);
            c.getLabel().ifPresent(l -> labels.put(path, l));
        }

        return labels;
    }

    private boolean existsLabel(String label) {
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

    public boolean disablePrompt() {
        isPrompting = false;
        return true;
    }

    public boolean enablePrompt() {
        isPrompting = true;
        return true;
    }
}
