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
import java.util.function.BooleanSupplier;
import java.util.function.Function;

// Note: de.swiesend.secretservice.interfaces.Prompt.Completed is referenced fully-qualified
// below to avoid a name clash with the low-level Prompt class in this package.

import static de.swiesend.secretservice.Static.DBus.DEFAULT_DELAY_MILLIS;
import static de.swiesend.secretservice.Static.DBus.MAX_DELAY_MILLIS;

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

    /**
     * Open a collection by its collection id (not label). This opens the collection
     * directly using the known object path for the collection id and does not try
     * to create it.
     */
    public static Optional<CollectionInterface> openById(String id, Optional<SessionInterface> maybeSession) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("The collection id must not be null or blank.");
        }
        Objects.requireNonNull(maybeSession, "maybeSession must not be null; use Optional.empty() instead");
        Collection c = new Collection();
        if (maybeSession.isEmpty()) {
            c.clearSessionAtClose = true;
        }
        if (!c.init(maybeSession)) {
            return Optional.empty();
        }

        // construct object path from id and wrap low-level collection
        try {
            c.collection = new de.swiesend.secretservice.Collection(id, c.connection);
            c.path = c.collection.getPath();
            c.label = c.collection.getLabel();
            c.id = id;
            return Optional.of(c);
        } catch (Exception e) {
            log.error("Could not open collection by id {}: {}", id, e.getMessage());
            return Optional.empty();
        }
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
        Optional<DBusPath> maybePath = getCollectionPath(label);

        if (maybePath.isEmpty()) {
            maybePath = createNewCollection(label);
        }

        return maybePath.flatMap(path -> getCollectionFromPath(path, label));
    }

    private Optional<DBusPath> createNewCollection(String label) {
        DBusPath path = null;
        Map<String, Variant> properties = de.swiesend.secretservice.Collection.createProperties(label);

        if (encryptedCollectionPassword.isEmpty()) {
            Optional<DBusPath> maybePath = createCollectionWithPrompt(properties);
            if (maybePath.isPresent()) {
                path = maybePath.get();
            } else {
                return Optional.empty();
            }
        } else if (service.isGnomeKeyringAvailable()) {
            Optional<DBusPath> maybePath = withoutPrompt.createWithMasterPassword(properties, encryptedCollectionPassword.get());
            if (maybePath.isPresent()) {
                path = maybePath.get();
            }
        }

        if (path == null) {
            // Poll for the CollectionCreated signal instead of sleeping a fixed interval and hoping
            // it arrived: under load the signal can take longer than one DEFAULT_DELAY_MILLIS tick,
            // which would spuriously report the collection as "not created".
            awaitUntil(() -> service.getService().getSignalHandler()
                    .getLastHandledSignal(Service.CollectionCreated.class, Static.ObjectPaths.SECRETS) != null);
            Service.CollectionCreated signal = service.getService().getSignalHandler().getLastHandledSignal(Service.CollectionCreated.class, Static.ObjectPaths.SECRETS);
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

    /**
     * Polls {@code condition} until it holds or {@link Static.DBus#MAX_DELAY_MILLIS} elapses,
     * checking every {@link Static.DBus#DEFAULT_DELAY_MILLIS}. Returns the final observed value.
     * This replaces fixed single-sleep waits for asynchronous D-Bus state (a lock taking effect,
     * a signal arriving): the happy path returns on the first check with no added latency, while a
     * slow daemon under load is tolerated up to the bound instead of racing a single tick.
     * Restores the interrupt flag and returns early if interrupted.
     */
    static boolean awaitUntil(BooleanSupplier condition) {
        if (condition.getAsBoolean()) {
            return true;
        }
        // Fully qualified: this package declares its own `System` class, which shadows java.lang.
        long deadline = java.lang.System.nanoTime() + MAX_DELAY_MILLIS * 1_000_000L;
        while (java.lang.System.nanoTime() < deadline) {
            try {
                Thread.sleep(DEFAULT_DELAY_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return condition.getAsBoolean();
            }
            if (condition.getAsBoolean()) {
                return true;
            }
        }
        return condition.getAsBoolean();
    }

    /** Null-safe check that {@code paths} contains an object at {@code objectPath}. Package-private for tests. */
    static boolean containsPath(List<DBusPath> paths, String objectPath) {
        return paths != null && paths.stream()
                .filter(Objects::nonNull)
                .anyMatch(p -> objectPath.equals(p.getPath()));
    }

    /**
     * Null-safe check that {@code prompt} is a real prompt. The Secret Service uses the sentinel
     * path {@code "/"} (and a missing path) to mean "no prompt required". Package-private for tests.
     */
    static boolean requiresPrompt(DBusPath prompt) {
        return prompt != null && prompt.getPath() != null && !"/".equals(prompt.getPath());
    }

    private Optional<DBusPath> createCollectionWithPrompt(Map<String, Variant> properties) {
        Optional<Pair<DBusPath, DBusPath>> maybeResponse = service.getService().createCollection(properties);
        if (maybeResponse.isEmpty()) {
            log.error("Could not create collection.");
            return Optional.empty();
        }
        Pair<DBusPath, DBusPath> response = maybeResponse.get();
        if (!"/".equals(response.a.getPath())) {
            return Optional.of(response.a);
        } else {
            return performPrompt(response.b);
        }
    }

    private Optional<de.swiesend.secretservice.Collection> getCollectionFromPath(DBusPath path, String label) {
        if (path == null) {
            log.error(String.format("Could not acquire collection with label: \"%s\"", label));
            return Optional.empty();
        }

        collection = new de.swiesend.secretservice.Collection(path, connection);
        return Optional.of(collection);
    }

    private Optional<DBusPath> getCollectionPath(String label) {
        Map<DBusPath, String> labels = getLabels();

        DBusPath path = null;
        for (Map.Entry<DBusPath, String> entry : labels.entrySet()) {
            DBusPath p = entry.getKey();
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

    private Optional<DBusPath> performPrompt(DBusPath path) {
        if (!isPrompting) {
            log.trace("dismissed the prompt");
            return Optional.empty();
        }
        if (!("/".equals(path.getPath()))) {
            return Optional.ofNullable(prompt.await(path, service.getTimeout()))
                    .filter(completed -> !completed.dismissed)
                    .map(success -> new DBusPath(success.result.getValue().toString()));
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
            log.error("No collection or session.");
            return Optional.empty();
        }

        unlock();

        Secret encrypted = session.getEncryptedSession().encrypt(secret).orElse(null);
        if (encrypted == null) {
            log.error("Could not encrypt secret for item \"{}\".", label);
            return Optional.empty();
        }

        try (encrypted) {
            Map<String, Variant> properties = Item.createProperties(label, attributes);
            Pair<DBusPath, DBusPath> pair = collection.createItem(properties, encrypted, false).orElse(null);
            if (pair == null || pair.a == null) {
                log.error("createItem D-Bus call returned no result for label \"{}\".", label);
                return Optional.empty();
            }

            // No prompt needed — item was created directly
            if (!"/".equals(pair.a.getPath())) {
                return Optional.of(pair.a.getPath());
            }

            // Prompt required (e.g. KeePassXC per-item unlock)
            de.swiesend.secretservice.interfaces.Prompt.Completed completed = prompt.await(pair.b);
            if (completed == null || completed.dismissed) {
                log.warn("Prompt was dismissed or timed out for item \"{}\".", label);
                return Optional.empty();
            }

            // KeePassXC returns the new item path directly in the prompt result
            String fromResult = extractItemPathFromPromptResult(completed);
            if (fromResult != null) {
                return Optional.of(fromResult);
            }

            // Fallback: wait for the ItemCreated signal scoped to this collection (gnome-keyring)
            de.swiesend.secretservice.Collection.ItemCreated sig = collection
                    .getSignalHandler()
                    .await(de.swiesend.secretservice.Collection.ItemCreated.class,
                            collection.getObjectPath(), () -> null, Duration.ofSeconds(5));
            if (sig != null && sig.item != null) {
                return Optional.of(sig.item.getPath());
            }

            log.warn("Did not observe ItemCreated signal for collection {} after prompt.", collection.getObjectPath());
            return Optional.empty();
        }
    }

    /**
     * Extracts a created item path from a {@link de.swiesend.secretservice.interfaces.Prompt.Completed} result.
     * <p>
     * KeePassXC returns the new item's DBus path inside the prompt result, either as a plain
     * {@link DBusPath}, a {@code List<DBusPath>}, or a nested {@code List<List<DBusPath>>}.
     *
     * @return the item path string, or {@code null} if none could be extracted
     */
    private String extractItemPathFromPromptResult(de.swiesend.secretservice.interfaces.Prompt.Completed completed) {
        if (completed.result == null) return null;
        Object rv = completed.result.getValue();
        if (rv == null) return null;
        try {
            if (rv instanceof List<?> list) {
                for (Object o : list) {
                    String path = pathFromObject(o);
                    if (path != null) return path;
                }
            } else {
                return pathFromObject(rv);
            }
        } catch (Exception e) {
            log.debug("Could not extract item path from prompt result: {}", e.getMessage());
        }
        return null;
    }

    /** Unwraps a DBusPath, String, or nested List thereof into a path string. */
    private static String pathFromObject(Object o) {
        if (o instanceof DBusPath p)  return p.getPath();
        if (o instanceof String s)    return s;
        if (o instanceof List<?> inner) {
            for (Object elem : inner) {
                if (elem instanceof DBusPath p) return p.getPath();
                if (elem instanceof String s)   return s;
            }
        }
        return null;
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

        Optional<DBusPath> maybePromptPath = item.delete();
        if (maybePromptPath.isEmpty()) {
            log.error("Could not delete item: {}", objectPath);
            return false;
        }
        DBusPath promptPath = maybePromptPath.get();
        Optional<DBusPath> performedPrompt = performPrompt(promptPath);
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
    public Optional<Boolean> itemExists(String objectPath) {
        // Deliberately no unlock() here: a locked item still answers the existence question (the
        // daemon refuses it by name, which is DENIED, i.e. present), and unlocking can prompt --
        // far too heavy for a question asked while classifying someone else's item.
        // empty, not of(false): a null path is a programming error and proves nothing about any
        // item. Answering "provably absent" would license a caller's destructive branch on it, and
        // every sibling method returns empty for the same input.
        if (Static.Utils.isNullOrEmpty(objectPath)) return Optional.empty();
        return getItem(objectPath).flatMap(de.swiesend.secretservice.Item::exists);
    }

    @Override
    public Optional<List<String>> getItems(Map<String, String> attributes) {
        if (attributes == null) return Optional.empty();
        unlock();

        // KeePassXC returns nothing for SearchItems({}) (empty map = no criteria match).
        // Use the Items property directly when no filter is specified — it always returns all items.
        // An empty result is a SUCCESSFUL search that found nothing, and must be reported as
        // Optional.of(emptyList). Optional.empty() is reserved for "the search failed". Conflating
        // them left callers unable to tell "no items" from "the daemon did not answer" -- which in
        // the hardened layer meant a key-destroying rotation could not tell whether it had proved
        // anything.
        if (attributes.isEmpty()) {
            return collection.getItems()
                    .map(Static.Convert::toStrings);
        }

        return Optional.ofNullable(collection.searchItems(attributes))
                .flatMap(objects -> objects.map(Static.Convert::toStrings));
    }

    @Override
    public List<String> search(String query, SearchMode mode) {
        Objects.requireNonNull(query, "query must not be null");
        Objects.requireNonNull(mode, "mode must not be null");
        Optional<List<String>> maybeAll = getItems(Map.of());
        if (maybeAll.isEmpty()) return List.of();
        List<String> all = maybeAll.get();
        if (query.isEmpty()) return all;
        String lq = query.toLowerCase(java.util.Locale.ROOT);
        List<String> matched = new ArrayList<>();
        for (String path : all) {
            if (matchesSubstring(path, lq, mode)) matched.add(path);
        }
        return java.util.Collections.unmodifiableList(matched);
    }

    @Override
    public List<String> search(String query, SearchMode mode, int maxDistance) {
        Objects.requireNonNull(query, "query must not be null");
        Objects.requireNonNull(mode, "mode must not be null");
        if (maxDistance < 0) throw new IllegalArgumentException("maxDistance must be >= 0");
        if (maxDistance == 0) return search(query, mode);
        Optional<List<String>> maybeAll = getItems(Map.of());
        if (maybeAll.isEmpty()) return List.of();
        List<String> all = maybeAll.get();
        if (query.isEmpty()) return all;
        String lq = query.toLowerCase(java.util.Locale.ROOT);
        List<String> matched = new ArrayList<>();
        for (String path : all) {
            if (matchesFuzzy(path, lq, mode, maxDistance)) matched.add(path);
        }
        return java.util.Collections.unmodifiableList(matched);
    }

    // ── Search helpers ─────────────────────────────────────────────

    private boolean matchesSubstring(String path, String lq, SearchMode mode) {
        return switch (mode) {
            case BY_NAME -> getItemLabel(path).orElse("").toLowerCase(java.util.Locale.ROOT).contains(lq);
            case BY_ATTRIBUTE_KEY -> getAttributes(path).orElse(Map.of()).keySet()
                    .stream().anyMatch(k -> k.toLowerCase(java.util.Locale.ROOT).contains(lq));
            case BY_ATTRIBUTE_VALUE -> getAttributes(path).orElse(Map.of()).values()
                    .stream().anyMatch(v -> v.toLowerCase(java.util.Locale.ROOT).contains(lq));
            case BY_OBJECT_ID -> {
                String id = path.contains("/") ? path.substring(path.lastIndexOf('/') + 1) : path;
                yield id.toLowerCase(java.util.Locale.ROOT).contains(lq);
            }
            case BY_OBJECT_PATH -> path.toLowerCase(java.util.Locale.ROOT).contains(lq);
        };
    }

    private boolean matchesFuzzy(String path, String lq, SearchMode mode, int maxDistance) {
        return switch (mode) {
            case BY_NAME -> {
                String candidate = getItemLabel(path).orElse("").toLowerCase(java.util.Locale.ROOT);
                yield Static.Utils.minSubstringDistance(candidate, lq) <= maxDistance;
            }
            case BY_ATTRIBUTE_KEY -> getAttributes(path).orElse(Map.of()).keySet().stream()
                    .anyMatch(k -> Static.Utils.minSubstringDistance(k.toLowerCase(java.util.Locale.ROOT), lq) <= maxDistance);
            case BY_ATTRIBUTE_VALUE -> getAttributes(path).orElse(Map.of()).values().stream()
                    .anyMatch(v -> Static.Utils.minSubstringDistance(v.toLowerCase(java.util.Locale.ROOT), lq) <= maxDistance);
            case BY_OBJECT_ID -> {
                String id = path.contains("/") ? path.substring(path.lastIndexOf('/') + 1) : path;
                yield Static.Utils.minSubstringDistance(id.toLowerCase(java.util.Locale.ROOT), lq) <= maxDistance;
            }
            case BY_OBJECT_PATH -> Static.Utils.minSubstringDistance(path.toLowerCase(java.util.Locale.ROOT), lq) <= maxDistance;
        };
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
            Optional<Pair<List<DBusPath>, DBusPath>> maybeLock = service.getService().lock(List.of(item.getPath()));
            if (maybeLock.isEmpty()) {
                log.error("Could not lock item: {}", itemPath);
                return false;
            }
            Pair<List<DBusPath>, DBusPath> lock = maybeLock.get();
            log.debug("lock item: {}", lock);
            de.swiesend.secretservice.interfaces.Prompt.Completed result = prompt.await(lock.b, service.getTimeout());
            log.debug("lock item prompt: {}", result);
        }
        return item.isLocked();
    }

    @Override
    public boolean unlockItem(String itemPath) {
        if (Static.Utils.isNullOrEmpty(itemPath)) {
            log.error("Cannot unlock an unspecified item.");
            return false;
        }
        Item item = new Item(Static.Convert.toObjectPath(itemPath), service.getService());
        if (item.isLocked()) {
            Optional<Pair<List<DBusPath>, DBusPath>> maybeUnlock = service.getService().unlock(List.of(item.getPath()));
            if (maybeUnlock.isEmpty()) {
                log.error("Could not unlock item: {}", itemPath);
                return false;
            }
            Pair<List<DBusPath>, DBusPath> unlock = maybeUnlock.get();
            log.debug("unlock item: {}", unlock);
            if (unlock.a.isEmpty()) {
                // A prompt is required. await() returns null when it times out, and reading
                // .result on that threw a NullPointerException out of a method declared to return
                // a boolean. A dismissed prompt was not checked at all, so a refusal looked the
                // same as a success until the re-read below happened to contradict it.
                de.swiesend.secretservice.interfaces.Prompt.Completed completed =
                        prompt.await(unlock.b, service.getTimeout());
                if (completed == null) {
                    log.warn("Unlock prompt for item {} timed out.", itemPath);
                    return false;
                }
                if (completed.dismissed) {
                    log.info("Unlock prompt for item {} was dismissed by the user.", itemPath);
                    return false;
                }
            }
        }
        // Authoritative: ask the provider again rather than trusting the prompt result.
        return !item.isLocked();
    }

    @Override
    public Optional<char[]> getSecret(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return Optional.empty();
        unlock();
        if (!unlockItemIfLocked(objectPath)) return Optional.empty();

        return getItem(objectPath)
                .flatMap(item -> {
                    DBusPath sessionPath = session.getSession().getPath();
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

        Optional<List<DBusPath>> maybeItems = collection.getItems();
        if (maybeItems.isEmpty()) return Optional.empty();

        List<DBusPath> items = maybeItems.get();

        Map<String, char[]> passwords = new HashMap<>();
        for (DBusPath item : items) {
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
        // Snapshot all values before the callback so that even if the callback
        // mutates the map (removes entries, clears it), we still zero every array.
        List<char[]> allValues = new ArrayList<>(secrets.values());
        try {
            return Optional.ofNullable(callback.apply(Collections.unmodifiableMap(secrets)));
        } finally {
            for (char[] value : allValues) {
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
        if (collection == null || collection.isLocked()) {
            // Nothing to do: no collection, or it is already locked.
            return collection != null && collection.isLocked();
        }
        Optional<Pair<List<DBusPath>, DBusPath>> maybeResult = service.getService().lock(lockable());
        if (maybeResult.isEmpty()) {
            log.error("D-Bus lock call failed for collection: \"" + collection.getLabel().orElse("?") + "\"");
            return false;
        }
        Pair<List<DBusPath>, DBusPath> result = maybeResult.get();

        // The Secret Service Lock method returns (locked, prompt): `locked` are the objects the
        // daemon locked immediately, `prompt` (!= "/") means it needs user interaction. Branch on
        // the response instead of blindly polling, so we neither race the "Locked" property nor
        // burn the timeout on a state that will never change.
        boolean lockedImmediately = containsPath(result.a, collection.getObjectPath());
        boolean promptRequired = requiresPrompt(result.b);

        if (lockedImmediately) {
            log.info("Locked collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
            // Daemon acknowledged the lock; poll only so the "Locked" property has time to
            // propagate (bounded by MAX_DELAY_MILLIS, returns on the first successful check).
            return awaitUntil(collection::isLocked);
        }
        if (promptRequired) {
            // Locking needs a prompt, which the functional layer does not drive here. Don't wait
            // out the timeout for a state that won't change -- report the failure immediately.
            log.warn("Locking collection \"" + collection.getLabel().orElse("?") + "\" ("
                    + collection.getObjectPath() + ") requires a prompt, which is not performed here; "
                    + "leaving it unlocked.");
            return false;
        }
        // Neither locked immediately nor prompted (e.g. a provider that does not support locking
        // this collection): reflect the daemon's current view without a long wait.
        return collection.isLocked();
    }

    private boolean unlock() {
        if (collection != null && collection.isLocked()) {
            if (encryptedCollectionPassword.isEmpty() || isDefault()) {
                Optional<Pair<List<DBusPath>, DBusPath>> maybeResponse = service.getService().unlock(lockable());
                if (maybeResponse.isPresent()) {
                    DBusPath promptPath = maybeResponse.get().b;
                    boolean unlockAccepted = promptPath.getPath().equals("/") || performPrompt(promptPath).isPresent();
                    if (unlockAccepted && !collection.isLocked()) {
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
        log.debug("Could not unlock collection: \"" + collection.getLabel().orElse("?") + "\" (" + collection.getObjectPath() + ")");
        return false;
    }

    @Override
    public boolean unlockWithUserPermission() {
        // Lock before unlocking to force a user prompt, preventing silent access by malicious apps.
        // Applies to all collections (not just default) as the safer policy (CVE-2018-19358).
        if (!isUnlockedOnceWithUserPermission) {
            if (!lock()) {
                log.error("Failed to lock collection before prompting for user permission.");
                return false;
            }
        }
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

    private Map<DBusPath, String> getLabels() {
        Optional<List<DBusPath>> maybeCollections = service.getService().getCollections();
        if (maybeCollections.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<DBusPath, String> labels = new HashMap<>();
        for (DBusPath path : maybeCollections.get()) {
            de.swiesend.secretservice.Collection c = new de.swiesend.secretservice.Collection(path, connection, null);
            c.getLabel().ifPresent(l -> labels.put(path, l));
        }

        return labels;
    }

    /**
     * Resolve the DBus object path (collection id) for a given display label.
     * Returns empty if no collection with the given label exists.
     */
    public Optional<String> getCollectionIdForLabel(String label) {
        if (label == null) return Optional.empty();
        Map<DBusPath, String> labels = getLabels();
        return labels.entrySet().stream()
                .filter(e -> label.equals(e.getValue()))
                .map(e -> e.getKey().getPath())
                .findFirst();
    }

    /**
     * Detects the currently active Secret Service provider and returns its display name.
     */
    @Override
    public String getProvider() {
        return detectProvider().displayName;
    }

    /**
     * Detects the currently active Secret Service provider as a typed enum constant.
     */
    @Override
    public de.swiesend.secretservice.ProviderDetector.Provider detectProvider() {
        return de.swiesend.secretservice.ProviderDetector.detectProvider(this.connection);
    }

    private boolean existsLabel(String label) {
        Map<DBusPath, String> labels = getLabels();
        return labels.containsValue(label);
    }

    private Optional<Item> getItem(String path) {
        if (path != null) {
            return Optional.of(new Item(Static.Convert.toObjectPath(path), service.getService()));
        } else {
            return Optional.empty();
        }
    }

    private List<DBusPath> lockable() {
        return Arrays.asList(collection.getPath());
    }

    /**
     * Unlocks a single item when the provider reports it as locked, so a read can proceed.
     *
     * <p>The freedesktop specification says a client "should act as if it must unlock each item
     * individually". KeePassXC does exactly that and prompts per item; gnome-keyring never locks an
     * item on its own, so it only ever needed the collection-level {@link #unlock()} above. Because
     * only the collection was unlocked, reading a locked item on KeePassXC simply failed
     * (issue #45).
     *
     * <p><b>Why this cannot change behaviour for existing consumers.</b> The new work happens only
     * inside the {@code isLocked()} branch, and that branch is unreachable on the providers people
     * use today:
     * <ul>
     *   <li>gnome-keyring does not lock items individually, so the property is false and nothing
     *       here runs.</li>
     *   <li>{@link de.swiesend.secretservice.Item#isLocked()} is <em>fail-open</em>: a property read
     *       that fails yields {@code false}. A flaky D-Bus call therefore cannot raise a prompt that
     *       did not appear before.</li>
     * </ul>
     * The only callers affected are those on a provider that genuinely locks items -- the case that
     * does not work at all today.
     *
     * <p>Deliberately not applied to {@code getSecrets}/{@code withSecrets}: those iterate the whole
     * collection, and one prompt per item is not a reasonable thing to do to a user.
     *
     * @return true when the item can be read: it was already unlocked, or the unlock succeeded.
     *         False when the item stayed locked, which includes the user dismissing the prompt.
     */
    private boolean unlockItemIfLocked(String objectPath) {
        Optional<de.swiesend.secretservice.Item> maybeItem = getItem(objectPath);
        if (maybeItem.isEmpty()) return true; // not our call to make; the read below reports it
        if (!maybeItem.get().isLocked()) return true;

        log.debug("Item is locked; asking the provider to unlock it: {}", objectPath);
        if (unlockItem(objectPath)) return true;

        // Do not fall through to GetSecret. It cannot succeed on a locked item, and the failure it
        // produces would be reported as a missing or unreadable secret rather than as the refusal
        // it actually is.
        log.warn("Item stayed locked, so its secret cannot be read: {}. The unlock prompt was "
                + "dismissed, timed out, or the provider refused it.", objectPath);
        return false;
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
