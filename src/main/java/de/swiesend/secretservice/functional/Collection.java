package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.*;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.freedesktop.dbus.DBusPath;
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
    private DBusPath path = null;
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
     * Open the default collection with an optional existing session.
     * @param maybeSession an existing session to reuse, or empty to create a new one
    public static Optional<CollectionInterface> openDefault(Optional<SessionInterface> maybeSession) {
        Objects.requireNonNull(maybeSession, "maybeSession must not be null; use Optional.empty() instead");
        Collection c = new Collection();
        if (maybeSession.isEmpty()) {
            c.clearSessionAtClose = true;
        }
        if (!c.init(maybeSession)) {
            return Optional.empty();
        c.path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        c.collection = new de.swiesend.secretservice.Collection(c.path, c.connection);
        c.label = c.collection.getLabel();
        c.id = c.collection.getId();
        return Optional.of(c);
     * Open or create a named collection, creating a new session automatically.
     * @param label the collection label
     * @return the collection, or empty if it could not be acquired
    public static Optional<CollectionInterface> open(String label) {
        return open(label, Optional.empty(), Optional.empty());
     * Open or create a named collection with an optional password.
     * @param label         the collection label
     * @param maybePassword optional collection password
    public static Optional<CollectionInterface> open(String label, Optional<CharSequence> maybePassword) {
        return open(label, maybePassword, Optional.empty());
     * Open or create a named collection with an optional password and session.
     * @param maybeSession  an existing session to reuse, or empty to create a new one
    public static Optional<CollectionInterface> open(String label, Optional<CharSequence> maybePassword, Optional<SessionInterface> maybeSession) {
        if (label == null || label.isBlank()) {
            throw new IllegalArgumentException("The collection label must not be null or blank.");
        Objects.requireNonNull(maybePassword, "maybePassword must not be null; use Optional.empty() instead");
        c.encryptedCollectionPassword = maybePassword.flatMap(
                password -> c.session.getEncryptedSession().encrypt(password)
        );
        Optional<de.swiesend.secretservice.Collection> maybeCollection = c.getOrCreateCollection(label);
        if (maybeCollection.isEmpty()) {
            log.warn("Could not acquire collection with name {}", label);
        c.collection = maybeCollection.get();
        c.path = c.collection.getPath();
        c.label = Optional.ofNullable(label);
    private boolean init(Optional<SessionInterface> maybeSession) {
            this.clearSessionAtClose = true;
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
        this.session = resolved.get();
        this.service = session.getService();
        this.connection = service.getService().getConnection();
        this.prompt = new Prompt(session.getService().getService());
        if (service.isGnomeKeyringAvailable()) {
            this.withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(session.getService().getService());
        return true;
    private Optional<de.swiesend.secretservice.Collection> getOrCreateCollection(String label) {
        Optional<DBusPath> maybePath = getCollectionPath(label);
        if (maybePath.isEmpty()) {
            maybePath = createNewCollection(label);
        return maybePath.flatMap(path -> getCollectionFromPath(path, label));
    private Optional<DBusPath> createNewCollection(String label) {
        DBusPath path = null;
        Map<String, Variant> properties = de.swiesend.secretservice.Collection.createProperties(label);
        if (encryptedCollectionPassword.isEmpty()) {
            Optional<DBusPath> maybePath = createCollectionWithPrompt(properties);
            if (maybePath.isPresent()) {
                path = maybePath.get();
            } else {
                return Optional.empty();
        } else if (service.isGnomeKeyringAvailable()) {
            Optional<DBusPath> maybePath = withoutPrompt.createWithMasterPassword(properties, encryptedCollectionPassword.get());
        if (path == null) {
            waitForCollectionCreatedSignal();
            Service.CollectionCreated signal = service.getService().getSignalHandler().getLastHandledSignal(Service.CollectionCreated.class);
            if (signal == null) {
                log.warn("Collection \"" + label + "\" was not created.");
            DBusPath signalPath = signal.collection;
            if (signalPath == null || signalPath.getPath() == null) {
                log.error(String.format("Received bad signal `CollectionCreated` without proper collection path: %s", signal));
            path = Static.Convert.toObjectPath(signalPath.getPath());
            log.error("Could not acquire a path for the prompt.");
        return Optional.ofNullable(path);
    private void waitForCollectionCreatedSignal() {
        try {
            Thread.sleep(DEFAULT_DELAY_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while waiting for a CollectionCreated signal.", e);
    private Optional<DBusPath> createCollectionWithPrompt(Map<String, Variant> properties) {
        Optional<Pair<DBusPath, DBusPath>> maybeResponse = service.getService().createCollection(properties);
        if (maybeResponse.isEmpty()) {
            log.error("Could not create collection.");
        Pair<DBusPath, DBusPath> response = maybeResponse.get();
        if (!"/".equals(response.a.getPath())) {
            return Optional.of(response.a);
            return performPrompt(response.b);
    private Optional<de.swiesend.secretservice.Collection> getCollectionFromPath(DBusPath path, String label) {
            log.error(String.format("Could not acquire collection with label: \"%s\"", label));
        collection = new de.swiesend.secretservice.Collection(path, connection);
        return Optional.of(collection);
    private Optional<DBusPath> getCollectionPath(String label) {
        Map<DBusPath, String> labels = getLabels();
        for (Map.Entry<DBusPath, String> entry : labels.entrySet()) {
            DBusPath p = entry.getKey();
            String l = entry.getValue();
            if (label.equals(l)) {
                path = p;
                break;
    private boolean isDefault() {
        if (connection != null && connection.isConnected()) {
            List<String> defaults = Arrays.asList(null, "login", "session", "default");
            return defaults.contains(collection.getId());
            log.error("No D-Bus connection: Cannot check if the collection is the default collection.");
            return false;
    private Optional<DBusPath> performPrompt(DBusPath path) {
        if (!isPrompting) {
            log.trace("dismissed the prompt");
        if (!("/".equals(path.getPath()))) {
            return Optional.ofNullable(prompt.await(path, service.getTimeout()))
                    .filter(completed -> !completed.dismissed)
                    .map(success -> new DBusPath(success.getSource(), success.result.getValue().toString()));
    @Override
    public boolean clear() {
        if (encryptedCollectionPassword.isPresent()) {
            boolean cleared = encryptedCollectionPassword.get().clear();
            encryptedCollectionPassword = Optional.empty();
            if (cleared) {
                log.trace("cleared collection password");
                log.trace("Could not clear collection password");
            return cleared;
            log.trace("No collection password to clear");
            return true;
    public Optional<String> createItem(String label, CharSequence secret) {
        return createItem(label, secret, null);
    public Optional<String> createItem(String label, CharSequence secret, Map<String, String> attributes) {
        if (Static.Utils.isNullOrEmpty(secret)) {
            log.error("The secret may not be null or empty.");
        if (label == null) {
            log.error("The label of the item may not be null.");
        if (collection == null || session.getEncryptedSession() == null) {
            log.error("Not collection or session");
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
    public boolean delete() {
        if (isDefault()) {
            log.error("The default collection shall only be deleted with the low-level API.");
        return collection.delete()
                .map(promptPath -> promptPath.getPath().equals("/") || performPrompt(promptPath).isPresent())
                .orElse(false);
    public boolean deleteItem(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) {
            log.error("Cannot delete an unspecified item.");
        unlockWithUserPermission();
        Optional<Item> maybeItem = getItem(objectPath);
        if (maybeItem.isEmpty()) {
            log.error("Item not found: {}", objectPath);
        Item item = maybeItem.get();
        Optional<DBusPath> maybePromptPath = item.delete();
        if (maybePromptPath.isEmpty()) {
            log.error("Could not delete item: {}", objectPath);
        DBusPath promptPath = maybePromptPath.get();
        Optional<DBusPath> performedPrompt = performPrompt(promptPath);
        if (service.isGnomeKeyringAvailable() && performedPrompt.isEmpty()) {
            // gnome-keyring returns no path;
            // KeePassXC returns an empty path
            return performedPrompt.isPresent();
    public boolean deleteItems(List<String> objectPaths) {
        if (objectPaths == null || objectPaths.isEmpty()) {
            log.error("Cannot delete unspecified items.");
        boolean allDeleted = true;
        for (String item : objectPaths) {
            boolean success = deleteItem(item);
            if (!success) {
                allDeleted = false;
        return allDeleted;
    public Optional<Map<String, String>> getAttributes(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return Optional.empty();
        return getItem(objectPath).flatMap(item -> item.getAttributes());
    public Optional<List<String>> getItems(Map<String, String> attributes) {
        if (attributes == null) return Optional.empty();
        return Optional.ofNullable(collection.searchItems(attributes))
                .filter(objects -> !objects.isEmpty())
                .flatMap(objects -> objects.map(Static.Convert::toStrings));
    public Optional<String> getItemLabel(String objectPath) {
        return getItem(objectPath)
                .flatMap(item -> item.getLabel());
    public boolean setItemLabel(String objectPath, String label) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return false;
            log.error("The label may not be null.");
                .map(item -> item.setLabel(label))
    public boolean setLabel(String label) {
        boolean success = collection.setLabel(label);
        if (success) {
            this.label = Optional.ofNullable(label);
        return success;
    public Optional<String> getLabel() {
        return this.label;
    public Optional<String> getId() {
        return Optional.of(this.collection.getId());
    public boolean lockItem(String itemPath) {
        if (Static.Utils.isNullOrEmpty(itemPath)) {
            log.error("Cannot lock an unspecified item.");
        Item item = new Item(Static.Convert.toObjectPath(itemPath), service.getService());
        if (!item.isLocked()) {
            Optional<Pair<List<DBusPath>, DBusPath>> maybeLock = service.getService().lock(List.of(item.getPath()));
            if (maybeLock.isEmpty()) {
                log.error("Could not lock item: {}", itemPath);
            Pair<List<DBusPath>, DBusPath> lock = maybeLock.get();
            log.debug("lock item: {}", lock);
            de.swiesend.secretservice.interfaces.Prompt.Completed result = prompt.await(lock.b, service.getTimeout());
            log.debug("lock item prompt: {}", result);
    public boolean unlockItem(String itemPath) {
            log.error("Cannot unlock an unspecified item.");
        if (item.isLocked()) {
            service.getService().unlock(List.of(item.getPath())).ifPresent(unlock -> {
                log.debug("unlock item: {}", unlock);
                if(unlock.a.isEmpty()){
                    de.swiesend.secretservice.interfaces.Prompt.Completed await = prompt.await(unlock.b, service.getTimeout());
                    log.info(String.format("Unlocked Item: %s", await.result.getValue()));
            });
    public Optional<char[]> getSecret(String objectPath) {
                .flatMap(item -> {
                    DBusPath sessionPath = session.getSession().getPath();
                    return item.getSecret(sessionPath);
                })
                .flatMap(secret -> {
                    try (secret) {
                        return session.getEncryptedSession().decrypt(secret);
    public <R> Optional<R> withSecret(String objectPath, Function<char[], R> callback) {
        Objects.requireNonNull(callback, "callback must not be null");
        Optional<char[]> maybeSecret = getSecret(objectPath);
        if (maybeSecret.isEmpty()) {
        char[] secret = maybeSecret.get();
            return Optional.ofNullable(callback.apply(secret));
        } finally {
            Arrays.fill(secret, '\0');
    public Optional<Map<String, char[]>> getSecrets() {
        if (!unlockWithUserPermission()) {
        Optional<List<DBusPath>> maybeItems = collection.getItems();
        if (maybeItems.isEmpty()) return Optional.empty();
        List<DBusPath> items = maybeItems.get();
        Map<String, char[]> passwords = new HashMap<>();
        for (DBusPath item : items) {
            String path = item.getPath();
            getSecret(path).ifPresent(secret -> passwords.put(path, secret));
        return Optional.of(passwords);
    public <R> Optional<R> withSecrets(Function<Map<String, char[]>, R> callback) {
        Optional<Map<String, char[]>> maybeSecrets = getSecrets();
        if (maybeSecrets.isEmpty()) {
        Map<String, char[]> secrets = maybeSecrets.get();
        // Snapshot all values before the callback so that even if the callback
        // mutates the map (removes entries, clears it), we still zero every array.
        List<char[]> allValues = new ArrayList<>(secrets.values());
            return Optional.ofNullable(callback.apply(Collections.unmodifiableMap(secrets)));
            for (char[] value : allValues) {
                Arrays.fill(value, '\0');
    public boolean isLocked() {
            return collection.isLocked();
            log.error("No D-Bus connection: Cannot check if the collection is locked.");
    public boolean lock() {
        if (collection != null && !collection.isLocked()) {
            Optional<Pair<List<DBusPath>, DBusPath>> result = service.getService().lock(lockable());
            if (result.isEmpty()) {
                log.error("D-Bus lock call failed for collection: \"" + collection.getLabel().orElse("?") + "\"");
            log.info("Locked collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
            try {
                Thread.sleep(DEFAULT_DELAY_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Interrupted while waiting for collection to lock.", e);
        return collection.isLocked();
    private boolean unlock() {
        if (collection != null && collection.isLocked()) {
            if (encryptedCollectionPassword.isEmpty() || isDefault()) {
                Optional<Pair<List<DBusPath>, DBusPath>> maybeResponse = service.getService().unlock(lockable());
                if (maybeResponse.isPresent()) {
                    DBusPath promptPath = maybeResponse.get().b;
                    if (performPrompt(promptPath).isPresent() && !collection.isLocked()) {
                        isUnlockedOnceWithUserPermission = true;
                        log.debug("Unlocked collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
                        return true;
            } else if (encryptedCollectionPassword.isPresent() && service.isGnomeKeyringAvailable()) {
                boolean result = withoutPrompt.unlockWithMasterPassword(collection.getPath(), encryptedCollectionPassword.get());
                if (result == true) {
                    log.debug("Unlocked collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
                return result;
        log.debug("Could not unlock collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
        return false;
    public boolean unlockWithUserPermission() {
        // Lock before unlocking to force a user prompt, preventing silent access by malicious apps.
        // Applies to all collections (not just default) as the safer policy (CVE-2018-19358).
        if (!isUnlockedOnceWithUserPermission) {
            if (!lock()) {
                log.error("Failed to lock collection before prompting for user permission.");
        if (collection.isLocked()) {
            log.error("The collection was not unlocked with user permission.");
    public boolean updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) {
            log.error("The object path of the item may not be null or empty.");
        if (Static.Utils.isNullOrEmpty(password)) {
            log.error("The password may not be null or empty.");
        if (label != null) {
            item.setLabel(label);
        if (attributes != null) {
            item.setAttributes(attributes);
        return session.getEncryptedSession().encrypt(password)
                .map(secret -> {
                    try (secret) { // auto-close
                        return item.setSecret(secret); // side-effect
    public void close() throws Exception {
        if (!isClosed) {
            clear();
            if (clearSessionAtClose) {
                // Close the service (which cascades to registered sessions and the
                // underlying SystemInterface/D-Bus connection). Closing only the session
                // would leak the D-Bus connection created internally by init().
                service.close();
        log.trace("closed collection");
        isClosed = true;
    private Map<DBusPath, String> getLabels() {
        Optional<List<DBusPath>> maybeCollections = service.getService().getCollections();
        if (maybeCollections.isEmpty()) {
            return Collections.emptyMap();
        Map<DBusPath, String> labels = new HashMap<>();
        for (DBusPath path : maybeCollections.get()) {
            de.swiesend.secretservice.Collection c = new de.swiesend.secretservice.Collection(path, connection, null);
            c.getLabel().ifPresent(l -> labels.put(path, l));
        return labels;
    private boolean existsLabel(String label) {
        return labels.containsValue(label);
    private Optional<Item> getItem(String path) {
        if (path != null) {
            return Optional.of(new Item(Static.Convert.toObjectPath(path), service.getService()));
    private List<DBusPath> lockable() {
        return Arrays.asList(collection.getPath());
    public boolean disablePrompt() {
        isPrompting = false;
    public boolean enablePrompt() {
        isPrompting = true;
}
