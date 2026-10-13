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
    Prompt prompt = null;
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
     * <p>
     * A provider that names no default collection is logged as a warning. The collection is then
     * the default alias's path, where reading and creating items fail.
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
        // The collection the alias points to, not the alias: getId() names it then, and the
        // signals the provider emits from the collection's own path reach it. The alias itself
        // where the provider names no default collection.
        Optional<DBusPath> alias = c.service.getService().readAlias("default");
        if (alias.isPresent() && "/".equals(alias.get().getPath())) {
            // "/" for no such alias. Nothing can be read from or created in the alias's path then,
            // and the failures come later, without a word on why: a fresh account where nothing
            // has created the login keyring yet, or a provider set up without a default.
            log.warn("The provider names no default collection; items of the default collection can be "
                    + "neither read nor created. Open a collection by its label instead, or set the "
                    + "provider's default.");
        }
        c.path = namedCollection(alias)
                .orElseGet(() -> Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION));
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
            log.warn("Could not acquire the collection.");
            c.closeAfterFailedOpen();
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
            c.closeAfterFailedOpen();
            return Optional.empty();
        }
    }

    /**
     * Releases what {@link #init} and the failed open acquired: the signal handlers, the encrypted
     * password, and the service when init() created it.
     */
    private void closeAfterFailedOpen() {
        try {
            close();
        } catch (Exception e) {
            log.warn("Could not release the collection after a failed open.", e);
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
        Map<String, Variant> properties = de.swiesend.secretservice.Collection.createProperties(label);

        // Only gnome-keyring's own interface takes a password. Every other provider creates a
        // collection through its prompt, where the user sets the password.
        if (encryptedCollectionPassword.isEmpty() || !service.isGnomeKeyringAvailable()) {
            if (encryptedCollectionPassword.isPresent()) {
                log.info("The provider is not gnome-keyring and cannot take the collection password; "
                        + "creating the collection through the provider's prompt.");
            }
            return createCollectionWithPrompt(properties);
        }

        Optional<DBusPath> created = withoutPrompt.createWithMasterPassword(properties, encryptedCollectionPassword.get());
        if (created.isPresent()) {
            return created;
        }
        // No reply is not proof of no collection: the reply can time out after gnome-keyring has
        // created it. Look it up by its label, never by the newest CollectionCreated signal: that
        // can be any collection that this connection saw created, by this client or another one,
        // and binding to it would write this collection's items into it and delete it on delete().
        if (awaitUntil(() -> getCollectionPath(label).isPresent())) {
            return getCollectionPath(label);
        }
        log.warn("The collection was not created.");
        return Optional.empty();
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
            log.error("Could not acquire the collection: it has no object path.");
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

    @Override
    public boolean isDefault() {
        if (connection != null && connection.isConnected()) {
            // gnome-keyring's login and session collections, and the alias path itself.
            List<String> defaults = Arrays.asList(null, "login", "session", "default");
            if (defaults.contains(collection.getId())) return true;
            // On every provider, the collection the default alias points to, which is how KWallet
            // and KeePassXC name their default.
            return defaultCollectionPath()
                    .map(path -> path.getPath().equals(collection.getObjectPath()))
                    .orElse(false);
        } else {
            log.error("No D-Bus connection: Cannot check if the collection is the default collection.");
            return false;
        }
    }

    /** The collection that the "default" alias points to, unless the provider names none. */
    private Optional<DBusPath> defaultCollectionPath() {
        return namedCollection(service.getService().readAlias("default"));
    }

    /** The collection that ReadAlias answered with, unless it answered "/", for none. */
    private static Optional<DBusPath> namedCollection(Optional<DBusPath> alias) {
        return alias.filter(path -> path.getPath() != null && !"/".equals(path.getPath()));
    }

    private Optional<DBusPath> performPrompt(DBusPath path) {
        if (!isPrompting) {
            // The provider allocated a Prompt object for this reply. Walking away leaves it
            // registered until the connection closes, one per call. requiresPrompt excludes "/",
            // which names no prompt object.
            if (requiresPrompt(path)) {
                dismissPrompt(path);
            }
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
        // A collection that stayed locked was refused: the user dismissed the unlock dialog, or
        // prompting is disabled. CreateItem on it would bring up the same dialog a second time.
        if (collection.isLocked()) {
            log.info("The collection stayed locked, so the item is not created.");
            return Optional.empty();
        }

        Secret encrypted = session.getEncryptedSession().encrypt(secret).orElse(null);
        if (encrypted == null) {
            log.error("Could not encrypt the secret for a new item in collection {}.", collection.getObjectPath());
            return Optional.empty();
        }

        try (encrypted) {
            Map<String, Variant> properties = Item.createProperties(label, attributes);
            Pair<DBusPath, DBusPath> pair = collection.createItem(properties, encrypted, false).orElse(null);
            if (pair == null || pair.a == null) {
                log.error("createItem D-Bus call returned no result in collection {}.", collection.getObjectPath());
                return Optional.empty();
            }

            // No prompt needed — item was created directly
            if (!"/".equals(pair.a.getPath())) {
                return Optional.of(pair.a.getPath());
            }

            // Prompt required (e.g. KeePassXC per-item unlock)
            if (!requiresPrompt(pair.b)) {
                // Neither an item nor a prompt, which the specification does not allow.
                log.error("createItem returned neither an item nor a prompt.");
                return Optional.empty();
            }
            if (!isPrompting) {
                log.debug("Creating the item needs a prompt, and prompting is disabled; dismissing it.");
                dismissPrompt(pair.b);
                return Optional.empty();
            }
            de.swiesend.secretservice.interfaces.Prompt.Completed completed =
                    prompt.await(pair.b, service.getTimeout());
            if (completed == null || completed.dismissed) {
                log.warn("Prompt was dismissed or timed out for a new item in collection {}.", collection.getObjectPath());
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
        return deleteItemAsked(objectPath);
    }

    /** Deletes the item after {@link #unlockWithUserPermission()} has been asked. */
    private boolean deleteItemAsked(String objectPath) {
        // A collection that stayed locked was refused: the user dismissed the unlock dialog, or
        // prompting is disabled. KWallet answers Delete on a closed wallet with "/" and deletes
        // nothing, which the check below would report as done.
        if (collection.isLocked()) {
            log.info("The collection stayed locked, so the item is not deleted: {}", objectPath);
            return false;
        }

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
        // "/" is the specification's "no prompt necessary": on an unlocked collection, the provider
        // has deleted the item. That holds for every provider, not only for gnome-keyring, which
        // was the one case accepted. Only a real prompt can still be dismissed, time out, or be
        // refused.
        if (!requiresPrompt(promptPath)) {
            return true;
        }
        return performPrompt(promptPath).isPresent();
    }

    @Override
    public boolean deleteItems(List<String> objectPaths) {
        if (objectPaths == null || objectPaths.isEmpty()) {
            log.error("Cannot delete unspecified items.");
            return false;
        }
        // Asked once for all of them: deleteItem() would ask again for every item.
        unlockWithUserPermission();
        if (collection.isLocked()) {
            log.info("The collection stayed locked, so no item is deleted.");
            return false;
        }

        boolean allDeleted = true;

        for (String item : objectPaths) {
            boolean success = !Static.Utils.isNullOrEmpty(item) && deleteItemAsked(item);
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

        // KeePassXC returns nothing for SearchItems({}) (empty map = no criteria match).
        // Use the Items property directly when no filter is specified — it always returns all items.
        if (attributes.isEmpty()) {
            return collection.getItems()
                    .filter(list -> !list.isEmpty())
                    .map(Static.Convert::toStrings);
        }

        return Optional.ofNullable(collection.searchItems(attributes))
                .filter(objects -> !objects.isEmpty())
                .flatMap(objects -> objects.map(Static.Convert::toStrings));
    }

    @Override
    public List<String> search(String query, SearchMode mode) {
        Objects.requireNonNull(query, "query must not be null");
        Objects.requireNonNull(mode, "mode must not be null");
        Optional<List<String>> maybeAll = getItems(Map.of());
        if (maybeAll.isEmpty()) return List.of();
        List<String> all = maybeAll.get();
        if (query.isEmpty()) return java.util.Collections.unmodifiableList(all);
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
        if (query.isEmpty()) return java.util.Collections.unmodifiableList(all);
        String lq = query.toLowerCase(java.util.Locale.ROOT);
        List<String> matched = new ArrayList<>();
        for (String path : all) {
            if (matchesFuzzy(path, lq, mode, maxDistance)) matched.add(path);
        }
        return java.util.Collections.unmodifiableList(matched);
    }

    // ── Search helpers ─────────────────────────────────────────────

    // Without unlock(): search() has asked once, through getItems(). The public getItemLabel() and
    // getAttributes() unlock first, and after a refused unlock that is one more dialog per item.
    private Optional<String> itemLabel(String path) {
        return getItem(path).flatMap(item -> item.getLabel());
    }

    private Optional<Map<String, String>> itemAttributes(String path) {
        return getItem(path).flatMap(item -> item.getAttributes());
    }

    private boolean matchesSubstring(String path, String lq, SearchMode mode) {
        return switch (mode) {
            case BY_NAME -> itemLabel(path).orElse("").toLowerCase(java.util.Locale.ROOT).contains(lq);
            case BY_ATTRIBUTE_KEY -> itemAttributes(path).orElse(Map.of()).keySet()
                    .stream().anyMatch(k -> k.toLowerCase(java.util.Locale.ROOT).contains(lq));
            case BY_ATTRIBUTE_VALUE -> itemAttributes(path).orElse(Map.of()).values()
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
                String candidate = itemLabel(path).orElse("").toLowerCase(java.util.Locale.ROOT);
                yield Static.Utils.minSubstringDistance(candidate, lq) <= maxDistance;
            }
            case BY_ATTRIBUTE_KEY -> itemAttributes(path).orElse(Map.of()).keySet().stream()
                    .anyMatch(k -> Static.Utils.minSubstringDistance(k.toLowerCase(java.util.Locale.ROOT), lq) <= maxDistance);
            case BY_ATTRIBUTE_VALUE -> itemAttributes(path).orElse(Map.of()).values().stream()
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
            // No isPrompting check before the call. Locking normally needs no prompt at all --
            // gnome-keyring answers Lock with a non-empty locked list and a "/" path -- and
            // disablePrompt() suppresses dialogs, not locking. Only the branch below can raise one.
            Optional<Pair<List<DBusPath>, DBusPath>> maybeLock = service.getService().lock(List.of(item.getPath()));
            if (maybeLock.isEmpty()) {
                log.error("Could not lock item: {}", itemPath);
                return false;
            }
            Pair<List<DBusPath>, DBusPath> lock = maybeLock.get();
            log.debug("lock item: {}", lock);
            // Only when a prompt is genuinely required: a non-empty lock.a means the provider
            // already locked the item, and "/" names no prompt object.
            if (lock.a.isEmpty() && requiresPrompt(lock.b)) {
                if (!isPrompting) {
                    log.debug("Locking item {} needs a prompt, and prompting is disabled; dismissing it.",
                            itemPath);
                    dismissPrompt(lock.b);
                } else {
                    de.swiesend.secretservice.interfaces.Prompt.Completed result =
                            prompt.await(lock.b, service.getTimeout());
                    log.debug("lock item prompt: {}", result);
                }
            }
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
            // Before the call, not after. Unlocking a locked item essentially always needs a
            // prompt, and issuing Unlock only to refuse the prompt leaves the provider holding a
            // Prompt object that is never answered nor dismissed -- one per read, for the life of
            // the connection, on a process that reads locked items with prompting disabled.
            if (!isPrompting) {
                log.debug("Unlocking item {} would need a prompt, and prompting is disabled.", itemPath);
                return false;
            }
            Optional<Pair<List<DBusPath>, DBusPath>> maybeUnlock = service.getService().unlock(List.of(item.getPath()));
            if (maybeUnlock.isEmpty()) {
                log.error("Could not unlock item: {}", itemPath);
                return false;
            }
            Pair<List<DBusPath>, DBusPath> unlock = maybeUnlock.get();
            log.debug("unlock item: {}", unlock);
            // requiresPrompt(), matching lockItem: an empty unlock.a with a "/" path means the
            // provider refused without offering a prompt.
            if (unlock.a.isEmpty() && requiresPrompt(unlock.b)) {
                // A prompt is required. await() returns null when it times out, and reading
                // .result on that threw a NullPointerException out of a method declared to return
                // a boolean. A dismissed prompt was not checked at all, so a refusal looked the
                // same as a success until the re-read below happened to contradict it.
                de.swiesend.secretservice.interfaces.Prompt.Completed completed =
                        prompt.await(unlock.b, service.getTimeout());
                // Logged, not returned on. await() answers null when the prompt timed out, which
                // does not tell whether the provider unlocked the item; the re-read below does.
                if (completed == null) {
                    log.warn("No prompt result for item {}; asking the provider directly.", itemPath);
                } else if (completed.dismissed) {
                    // Trustworthy: requiresPrompt(unlock.b) above guarantees a real prompt path,
                    // for which SignalHandler.await filters the Completed signal by path.
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
        return getSecret(objectPath, true);
    }

    /**
     * A locked item is not read: gnome-keyring and KeePassXC refuse to read one, but KWallet
     * answers with an empty secret (KDE bug 524650), which would pass for the item's own.
     *
     * @param unlockIfLocked whether to unlock the collection and a locked item first, which can
     *                       raise a prompt. False for the bulk readers, which have unlocked every
     *                       locked item at once and read only those found unlocked: one prompt per
     *                       item is not a reasonable thing to do to a user.
     */
    private Optional<char[]> getSecret(String objectPath, boolean unlockIfLocked) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return Optional.empty();
        try {
            if (unlockIfLocked) {
                unlock();
                if (!unlockItemIfLocked(objectPath)) return Optional.empty();
            }

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
        } catch (RuntimeException e) {
            // A reply that the code above does not expect. An empty result, as for any secret that
            // cannot be read: getSecrets() then skips this item, and does not drop the secrets it
            // has decrypted already, which nothing would erase.
            log.error("Could not read the secret of item {}", objectPath, e);
            return Optional.empty();
        }
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

        // Each item's lock is read once, here.
        List<DBusPath> locked = new ArrayList<>();
        for (DBusPath item : items) {
            if (isItemLocked(item.getPath())) locked.add(item);
        }
        Set<String> stillLocked = locked.isEmpty() ? Set.of() : unlockItems(locked);

        Map<String, char[]> passwords = new HashMap<>();
        for (DBusPath item : items) {
            String path = item.getPath();
            if (stillLocked.contains(path)) {
                log.debug("Item {} stayed locked; not read.", path);
                continue;
            }
            getSecret(path, false).ifPresent(secret -> passwords.put(path, secret));
        }

        return Optional.of(passwords);
    }

    /**
     * Unlocks {@code locked}, items of this collection, with one Unlock call, and answers the paths
     * of those that stay locked.
     *
     * <p>KeePassXC keeps an item locked for a client until the user confirms that client's access,
     * which it asks by default, and shows one dialog for all the items of an Unlock call. One call
     * per item, as {@link #unlockItemIfLocked} makes, would bring up a dialog per item. The prompt
     * is carried out whenever the provider gives one, also when some items came back unlocked
     * without it: the prompt unlocks the rest.</p>
     *
     * <p>Not with prompting disabled: a locked item unlocks only through a prompt. Nor in a
     * collection that is not known to be unlocked, for the reason {@link #unlockItemIfLocked}
     * gives: gnome-keyring reports every item locked while its collection is, and an unlock would
     * bring up a second dialog for the collection the user has just refused.</p>
     */
    private Set<String> unlockItems(List<DBusPath> locked) {
        Set<String> paths = new HashSet<>();
        for (DBusPath item : locked) paths.add(item.getPath());
        if (!isPrompting) {
            log.debug("{} items are locked, and prompting is disabled.", locked.size());
            return paths;
        }
        Optional<Boolean> collectionLocked = collection.lockedState();
        if (collectionLocked.isEmpty() || collectionLocked.get()) {
            log.debug("{} items are locked, and their collection is not known to be unlocked.", locked.size());
            return paths;
        }
        Optional<Pair<List<DBusPath>, DBusPath>> maybeUnlock = service.getService().unlock(locked);
        if (maybeUnlock.isEmpty()) {
            log.error("Could not unlock {} locked items.", locked.size());
            return paths;
        }
        DBusPath promptPath = maybeUnlock.get().b;
        if (requiresPrompt(promptPath)) {
            de.swiesend.secretservice.interfaces.Prompt.Completed completed =
                    prompt.await(promptPath, service.getTimeout());
            if (completed == null) {
                log.warn("No result from the prompt that unlocks {} items; asking the provider directly.",
                        locked.size());
            } else if (completed.dismissed) {
                log.info("The prompt that unlocks {} items was dismissed.", locked.size());
            }
        }
        // The provider's state, not the prompt result, is the authority.
        Set<String> stillLocked = new HashSet<>();
        for (String path : paths) {
            if (isItemLocked(path)) stillLocked.add(path);
        }
        return stillLocked;
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
        return lock(true) == Locking.LOCKED;
    }

    private enum Locking { LOCKED, NEEDS_A_PROMPT, FAILED }

    /**
     * @param withPrompt whether to carry out a lock that the provider puts behind a prompt. When
     *                   false, or when prompting is disabled, the prompt is dismissed instead and the
     *                   collection stays unlocked.
     */
    private Locking lock(boolean withPrompt) {
        if (collection == null) return Locking.FAILED;
        // Nothing to do: it is already locked.
        if (collection.isLocked()) return Locking.LOCKED;
        Optional<Pair<List<DBusPath>, DBusPath>> maybeResult = service.getService().lock(lockable());
        if (maybeResult.isEmpty()) {
            log.error("D-Bus lock call failed for collection {}", collection.getObjectPath());
            return Locking.FAILED;
        }
        Pair<List<DBusPath>, DBusPath> result = maybeResult.get();

        // The Secret Service Lock method returns (locked, prompt): `locked` are the objects the
        // daemon locked immediately, `prompt` (!= "/") means it needs user interaction. Branch on
        // the response instead of blindly polling, so we neither race the "Locked" property nor
        // burn the timeout on a state that will never change.
        boolean lockedImmediately = containsPath(result.a, collection.getObjectPath());
        boolean promptRequired = requiresPrompt(result.b);

        if (lockedImmediately) {
            log.info("Locked collection {}", collection.getObjectPath());
            // Daemon acknowledged the lock; poll only so the "Locked" property has time to
            // propagate (bounded by MAX_DELAY_MILLIS, returns on the first successful check).
            return awaitUntil(collection::isLocked) ? Locking.LOCKED : Locking.FAILED;
        }
        if (promptRequired) {
            // KeePassXC answers Lock with a prompt and locks only once the prompt is called. It
            // shows no dialog for that.
            if (!withPrompt || !isPrompting) {
                dismissPrompt(result.b);
                return Locking.NEEDS_A_PROMPT;
            }
            de.swiesend.secretservice.interfaces.Prompt.Completed completed =
                    prompt.await(result.b, service.getTimeout());
            if (completed != null && !completed.dismissed) {
                awaitUntil(collection::isLocked);
            }
            // The provider's state, not the prompt result, is the authority.
            return collection.isLocked() ? Locking.LOCKED : Locking.FAILED;
        }
        // Neither locked immediately nor prompted (e.g. a provider that does not support locking
        // this collection): reflect the daemon's current view without a long wait.
        return collection.isLocked() ? Locking.LOCKED : Locking.FAILED;
    }

    private boolean unlock() {
        if (collection != null && collection.isLocked()) {
            // The stored password works only through gnome-keyring's own interface. On any other
            // provider the prompt is the only way to unlock, password or not.
            if (encryptedCollectionPassword.isEmpty() || isDefault() || !service.isGnomeKeyringAvailable()) {
                Optional<Pair<List<DBusPath>, DBusPath>> maybeResponse = service.getService().unlock(lockable());
                if (maybeResponse.isPresent()) {
                    DBusPath promptPath = maybeResponse.get().b;
                    boolean unlockAccepted = promptPath.getPath().equals("/") || performPrompt(promptPath).isPresent();
                    if (unlockAccepted && !collection.isLocked()) {
                        isUnlockedOnceWithUserPermission = true;
                        log.debug("Unlocked collection {}", collection.getObjectPath());
                        return true;
                    }
                }
            } else if (encryptedCollectionPassword.isPresent() && service.isGnomeKeyringAvailable()) {
                boolean result = withoutPrompt.unlockWithMasterPassword(collection.getPath(), encryptedCollectionPassword.get());
                if (result == true) {
                    log.debug("Unlocked collection {}", collection.getObjectPath());
                }
                return result;
            }
            // Inside the branch: a collection that was not locked was not refused.
            log.debug("Could not unlock collection {}", collection.getObjectPath());
        }
        return false;
    }

    /** Whether {@link #unlock()} takes the stored-password branch, which shows no dialog. */
    private boolean canUnlockWithoutPrompt() {
        return encryptedCollectionPassword.isPresent() && !isDefault() && service.isGnomeKeyringAvailable();
    }

    @Override
    public boolean unlockWithUserPermission() {
        // Lock before unlocking to force a user prompt, preventing silent access by malicious apps.
        // Applies to all collections (not just default) as the safer policy (CVE-2018-19358).
        if (!isUnlockedOnceWithUserPermission) {
            // With prompting disabled, only gnome-keyring's stored-password unlock can undo the
            // lock below. Without it the collection would stay locked for every application on
            // the desktop -- for the login keyring, all of them would start to prompt -- and the
            // caller would still be refused.
            if (!isPrompting && !canUnlockWithoutPrompt()) {
                log.debug("Prompting is disabled, and nothing could unlock the collection again; not locking it.");
                return false;
            }
            switch (lock(false)) {
                case LOCKED -> {
                    // unlock() below brings up the provider's dialog.
                }
                case NEEDS_A_PROMPT -> {
                    // The provider locks only through a prompt: KeePassXC. Carrying it out would lock
                    // the user's database in KeePassXC's own window, only to bring up its unlock
                    // dialog, and KeePassXC confirms access to its secrets itself. So the collection
                    // is used as it is, as in 1.x.
                    log.debug("The provider locks only through a prompt; using the collection as it is.");
                    return !collection.isLocked();
                }
                case FAILED -> {
                    log.error("Failed to lock collection before prompting for user permission.");
                    return false;
                }
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

        // null keeps the secret, as a null label or attributes map keeps those, which is how 1.x
        // updated only an item's label. An empty secret is refused, as createItem refuses it.
        if (password != null && Static.Utils.isNullOrEmpty(password)) {
            log.error("The password may not be empty.");
            return false;
        }

        unlock();

        Optional<Item> maybeItem = getItem(objectPath);
        if (maybeItem.isEmpty()) {
            log.error("Item not found: {}", objectPath);
            return false;
        }
        Item item = maybeItem.get();

        // The specification: a locked item cannot be modified. Providers differ in what they take
        // from one: KWallet keeps a new label and drops the secret, and KeePassXC, which keeps an item
        // locked for a client until the user confirms its access, takes the label and the attributes
        // and refuses the secret. So the item is unlocked first, as for a read, and left as it is
        // when it stays locked.
        if (!unlockItemIfLocked(objectPath)) {
            log.info("Item {} stayed locked, so it is not changed.", objectPath);
            return false;
        }

        // Every part is attempted, as in 1.x, and the update succeeds only if each one did.
        boolean updated = true;
        if (label != null && !item.setLabel(label)) {
            log.error("Could not set the label of item {}", objectPath);
            updated = false;
        }

        if (attributes != null && !item.setAttributes(attributes)) {
            log.error("Could not set the attributes of item {}", objectPath);
            updated = false;
        }

        if (password != null) {
            boolean secretSet = session.getEncryptedSession().encrypt(password)
                    .map(secret -> {
                        try (secret) { // auto-close
                            return item.setSecret(secret); // side-effect
                        }
                    })
                    .orElse(false);
            if (!secretSet) {
                log.error("Could not set the secret of item {}", objectPath);
                updated = false;
            }
        }
        return updated;
    }

    @Override
    public void close() throws Exception {
        if (!isClosed) {
            clear();
            // This collection's own signal handlers. The connection usually outlives the
            // collection -- SimpleCollection's, or a session's that opens several -- and keeps
            // them registered otherwise.
            if (prompt != null) prompt.getSignalHandler().disconnect();
            if (collection != null) collection.getSignalHandler().disconnect();
            // The session keeps the collections it has to close; this one is closed.
            if (session instanceof Session owner) owner.forget(this);
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
     * Unlocks a single item when the provider reports it as locked, so a read or a change can
     * proceed.
     *
     * <p>The freedesktop specification says a client "should act as if it must unlock each item
     * individually". KeePassXC does exactly that and prompts per item; gnome-keyring never locks an
     * item on its own, so it only ever needed the collection-level {@link #unlock()} above. Because
     * only the collection was unlocked, reading a locked item on KeePassXC simply failed
     * (issue #45).
     *
     * <p><b>Only when the collection is already unlocked.</b> "The item reports locked" is not the
     * per-item condition, because gnome-keyring reports every item as locked while its collection
     * is locked -- verified against a live daemon. Acting on that alone means a failed
     * collection-level unlock (a dismissed prompt, a wrong stored password, {@code disablePrompt()})
     * is followed by a <em>second</em> prompt for the keyring the user has just refused. Collection
     * unlocked but item locked is the real condition, and the only one acted on.
     *
     * <p>The check is deliberately <b>fail-closed</b>: {@link #lockedState()} separates "could not
     * read it" from "unlocked", and both "locked" and "unknown" skip the unlock and the read.
     * {@link de.swiesend.secretservice.Collection#isLocked()} collapses them to {@code false},
     * which here would mean a transient read failure silently re-enables the double prompt.
     *
     * <p>Not applied to {@code getSecrets}/{@code withSecrets}, which iterate the whole collection:
     * one prompt per item is not a reasonable thing to do to a user. They unlock every locked item
     * with one Unlock call, through {@link #unlockItems}, and read through the private
     * {@code getSecret(path, false)}.
     *
     * @return true when the item can be read or changed: it was already unlocked, or the unlock
     *         succeeded. False when the item stayed locked, which includes the user dismissing the
     *         prompt.
     */
    private boolean unlockItemIfLocked(String objectPath) {
        // The collection must already be unlocked. gnome-keyring reports EVERY item as locked while
        // its collection is locked -- verified against a live daemon -- so without this guard the
        // branch below is reachable there, not only on a provider that locks items individually.
        // The damage: the preceding unlock() may have failed because the user dismissed the keyring
        // prompt, or the stored password is wrong, or disablePrompt() is set. Asking for a per-item
        // unlock then raises a SECOND prompt for the keyring they just refused. Collection unlocked
        // but item locked is the genuine per-item condition, and it is the only one we act on.
        if (connection == null || !connection.isConnected() || collection == null) return true;

        // The item first: on every provider that does not lock items, this is the only read this
        // method performs, and the method returns here.
        Optional<de.swiesend.secretservice.Item> maybeItem = getItem(objectPath);
        if (maybeItem.isEmpty()) return true; // getItem is empty only for a null path, rejected above
        if (!maybeItem.get().isLocked()) return true;

        // No isPrompting check here: unlockItem itself now refuses to raise a prompt the caller
        // opted out of, so the guarantee holds for direct callers of the public method too, and
        // stating it twice would let the two copies drift.

        Optional<Boolean> collectionLocked = collection.lockedState();
        // Empty means the read failed. Treating that as "unlocked" would re-enable the double
        // prompt on any transient D-Bus error, so unknown skips the unlock, and the read, just like
        // locked does.
        if (collectionLocked.isEmpty() || collectionLocked.get()) {
            log.debug("Item {} is locked, and its collection is not known to be unlocked.", objectPath);
            return false;
        }

        log.debug("Item is locked; asking the provider to unlock it: {}", objectPath);
        if (unlockItem(objectPath)) return true;

        // Do not fall through to GetSecret, or to a change. A read cannot succeed on a locked item,
        // and the failure it produces would be reported as a missing or unreadable secret rather
        // than as the refusal it actually is.
        // WARN only when something unexpected happened. With prompting disabled the item staying
        // locked is the caller's own instruction being carried out, and warning about it would
        // report a deliberate configuration as a fault on every read.
        if (isPrompting) {
            log.warn("Item stayed locked: {}. The unlock prompt was dismissed, timed out, or the "
                    + "provider refused it.", objectPath);
        } else {
            log.debug("Item {} stayed locked because prompting is disabled.", objectPath);
        }
        return false;
    }

    /**
     * Whether the provider reports the item as locked, for the bulk readers, which unlock the
     * locked items at once and skip those that stay locked. False also when that cannot be read, as
     * {@link de.swiesend.secretservice.Item#isLocked()} answers then.
     */
    private boolean isItemLocked(String objectPath) {
        return getItem(objectPath).map(de.swiesend.secretservice.Item::isLocked).orElse(false);
    }

    /**
     * Dismisses the prompt at {@code promptPath}, addressing that prompt's own object path. The
     * shared {@link Prompt} cannot do this: its Dismiss goes to whatever object path its last
     * {@code prompt()} call set, initially "/", which may belong to an unrelated prompt.
     */
    private void dismissPrompt(DBusPath promptPath) {
        boolean dismissed = service.getService().getMessageHandler()
                .send(Static.Service.SECRETS, promptPath.getPath(), Static.Interfaces.PROMPT,
                        "Dismiss", "")
                .isPresent();
        if (!dismissed) {
            log.debug("Could not dismiss the refused prompt at {}; the provider keeps it until "
                    + "this connection closes.", promptPath.getPath());
        }
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
