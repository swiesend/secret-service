package de.swiesend.secretservice.tools.gui;

import de.swiesend.secretservice.functional.SearchMode;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import de.swiesend.secretservice.interfaces.Collection.ItemChanged;
import de.swiesend.secretservice.interfaces.Collection.ItemCreated;
import de.swiesend.secretservice.interfaces.Collection.ItemDeleted;
import de.swiesend.secretservice.interfaces.Prompt.Completed;
import de.swiesend.secretservice.interfaces.Service.CollectionChanged;
import de.swiesend.secretservice.interfaces.Service.CollectionCreated;
import de.swiesend.secretservice.interfaces.Service.CollectionDeleted;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

/**
 * What the window does with the keyring, through the library's functional API and without Swing:
 * it holds the connection, the session and the open collection, and reports each step to the log.
 *
 * <p>Its calls wait for the provider, and for the user where the provider asks through a dialog.
 * The window makes them on its {@link Worker}, one after the other, and never on the event
 * thread; the client is not safe for use by several threads at once.</p>
 */
final class KeyringClient {

    /**
     * A collection of the provider.
     *
     * @param isDefault whether it is a default collection by the library's rule: the one that the
     *                  {@code default} alias names, or gnome-keyring's {@code login} or
     *                  {@code session} collection
     * @param locked    empty where the provider does not say
     */
    record CollectionEntry(String path, String id, String label, boolean isDefault, Optional<Boolean> locked) {
    }

    /** The collection that the window opened. */
    record Opened(String label, String id, boolean isDefault, boolean locked) {
    }

    /**
     * What an open came to: the collection, nothing, or a default collection that the user has
     * not acknowledged the risk for, which the client closed again.
     */
    record OpenOutcome(Optional<Opened> opened, boolean needsAcknowledgement) {
        static OpenOutcome failed() {
            return new OpenOutcome(Optional.empty(), false);
        }
    }

    /** What the window shows of the selected item. */
    record ItemDetail(String path, String label, Map<String, String> attributes) {
    }

    /** One line of a state table. */
    record Row(String property, String value) {
    }

    /** What the library's objects report about themselves, for the Debug tab. */
    record State(boolean busConnected, boolean serviceAvailable, String provider,
                 List<Row> system, List<Row> service, List<Row> session, List<Row> collection) {
    }

    /** The ids of gnome-keyring's default collections, which the library treats as default by their id. */
    private static final Set<String> DEFAULT_IDS = Set.of("login", "session", "default");

    private final Consumer<String> log;
    private final List<AutoCloseable> signals = new ArrayList<>();

    private SystemInterface system;
    private ServiceInterface service;
    private SessionInterface session;
    private CollectionInterface collection;
    private boolean wasUnlockedOnce = false;

    /**
     * @param log takes the lines for the window's log, from any thread
     */
    KeyringClient(Consumer<String> log) {
        this.log = log;
    }

    private void log(String format, Object... args) {
        log.accept(String.format(format, args));
    }

    // -- Connect / disconnect --

    /**
     * Connects to the bus, the provider and a session, without opening a collection.
     *
     * @return the provider's collections, or empty where the connection failed
     */
    Optional<List<CollectionEntry>> connect() {
        disconnect();
        try {
            Optional<SystemInterface> maybeSystem = de.swiesend.secretservice.functional.System.connect();
            if (maybeSystem.isEmpty()) {
                log("ERROR: Could not connect to D-Bus.");
                return Optional.empty();
            }
            system = maybeSystem.get();
            log("D-Bus connection established.");
            registerSignalLoggers();

            Optional<ServiceInterface> maybeService = SecretService.create(Optional.of(system));
            if (maybeService.isEmpty()) {
                log("ERROR: Secret service not available.");
                disconnect();
                return Optional.empty();
            }
            service = maybeService.get();
            log("Secret service created. Gnome Keyring: %s", service.isGnomeKeyringAvailable());

            Optional<SessionInterface> maybeSession = service.openSession();
            if (maybeSession.isEmpty()) {
                log("ERROR: Could not open session.");
                disconnect();
                return Optional.empty();
            }
            session = maybeSession.get();
            log("Session opened: %s", session.getId());
            return Optional.of(listCollections());
        } catch (RuntimeException e) {
            disconnect();
            throw e;
        }
    }

    /**
     * The provider's collections, which the functional API does not list: through the
     * {@code Collections} property of the service, and each collection's own properties.
     */
    List<CollectionEntry> listCollections() {
        de.swiesend.secretservice.Service lowLevel = connected().getService();
        Optional<String> alias = defaultAlias();
        List<CollectionEntry> entries = new ArrayList<>();
        for (DBusPath path : lowLevel.getCollections().orElse(List.of())) {
            // Without signals: the entry only reads two properties.
            de.swiesend.secretservice.Collection collection =
                    new de.swiesend.secretservice.Collection(path, system.getConnection(), List.of());
            String id = collection.getId();
            boolean isDefault = DEFAULT_IDS.contains(id) || alias.map(path.getPath()::equals).orElse(false);
            String label = collection.getLabel().filter(name -> !name.isBlank()).orElse(id);
            entries.add(new CollectionEntry(path.getPath(), id, label, isDefault, collection.lockedState()));
        }
        entries.sort(Comparator.comparing(CollectionEntry::isDefault).reversed()
                .thenComparing(CollectionEntry::label, String.CASE_INSENSITIVE_ORDER));
        log("Listed %d collection(s).", entries.size());
        return entries;
    }

    /**
     * Opens a collection of the list, a default one only where the user has acknowledged the risk.
     */
    OpenOutcome open(CollectionEntry entry, boolean defaultAcknowledged) {
        if (entry.isDefault() && !defaultAcknowledged) return new OpenOutcome(Optional.empty(), true);
        // The one that the alias names opens through the alias, as an application opens it.
        boolean aliasTarget = defaultAlias().map(entry.path()::equals).orElse(false);
        return opened(aliasTarget ? connectedSession().defaultCollection()
                : connectedSession().collectionById(entry.id()), defaultAcknowledged);
    }

    /** The path of the collection that the {@code default} alias names, if it names one. */
    private Optional<String> defaultAlias() {
        return connected().getService().readAlias("default")
                .map(DBusPath::getPath)
                .filter(path -> !"/".equals(path));
    }

    /**
     * Opens the collection with that label, which the provider creates if it has none: with the
     * password, or through the provider's dialog where it is empty. A default collection that has
     * the label opens only where the user has acknowledged the risk.
     */
    OpenOutcome create(String label, CharSequence password, boolean defaultAcknowledged) {
        log("Opening collection by label: %s", label);
        Optional<CharSequence> maybePassword = password.length() == 0 ? Optional.empty() : Optional.of(password);
        return opened(connectedSession().collection(label, maybePassword), defaultAcknowledged);
    }

    private OpenOutcome opened(Optional<CollectionInterface> maybeCollection, boolean defaultAcknowledged) {
        if (maybeCollection.isEmpty()) {
            log("ERROR: Could not open collection.");
            return OpenOutcome.failed();
        }
        CollectionInterface opened = maybeCollection.get();
        boolean isDefault = opened.isDefault();
        if (isDefault && !defaultAcknowledged) {
            log("Not opened: the collection is a default collection. Open it from the list.");
            closeQuietly(opened);
            return new OpenOutcome(Optional.empty(), true);
        }
        closeCollection();
        collection = opened;
        String label = collection.getLabel().orElse("?");
        String id = collection.getId().orElse("?");
        log("Connected to collection label=\"%s\" id=\"%s\"%s.", label, id, isDefault ? " (default)" : "");
        boolean locked = collection.isLocked();
        if (!locked) wasUnlockedOnce = true;
        log("Locked: %s", locked);
        return new OpenOutcome(Optional.of(new Opened(label, id, isDefault, locked)), false);
    }

    /** Closes the open collection, and keeps the session. */
    void closeCollection() {
        if (collection != null) closeQuietly(collection);
        collection = null;
        wasUnlockedOnce = false;
    }

    private static void closeQuietly(CollectionInterface collection) {
        try {
            collection.close();
        } catch (Exception ignored) {
        }
    }

    /** Closes the service, which closes its sessions, their collections and the connection. */
    void disconnect() {
        for (AutoCloseable signal : signals) {
            try {
                signal.close();
            } catch (Exception ignored) {
            }
        }
        signals.clear();
        if (service != null) {
            try {
                service.close();
            } catch (Exception ignored) {
            }
        } else if (system != null) {
            try {
                system.disconnect();
            } catch (Exception ignored) {
            }
        }
        service = null;
        session = null;
        collection = null;
        system = null;
        wasUnlockedOnce = false;
    }

    private void registerSignalLoggers() {
        DBusConnection connection = system.getConnection();
        try {
            signals.add(connection.addSigHandler(CollectionCreated.class,
                    s -> log("> CollectionCreated(%s)", s.collection)));
            signals.add(connection.addSigHandler(CollectionChanged.class,
                    s -> log("> CollectionChanged(%s)", s.collection)));
            signals.add(connection.addSigHandler(CollectionDeleted.class,
                    s -> log("> CollectionDeleted(%s)", s.collection)));
            signals.add(connection.addSigHandler(ItemCreated.class,
                    s -> log("> ItemCreated(%s) on %s", s.item, s.getPath())));
            signals.add(connection.addSigHandler(ItemChanged.class,
                    s -> log("> ItemChanged(%s) on %s", s.item, s.getPath())));
            signals.add(connection.addSigHandler(ItemDeleted.class,
                    s -> log("> ItemDeleted(%s) on %s", s.item, s.getPath())));
            signals.add(connection.addSigHandler(Completed.class,
                    s -> log("> Prompt.Completed(%s) dismissed=%s", s.getPath(), s.dismissed)));
            log("Signal loggers registered (7 D-Bus signals).");
        } catch (Exception e) {
            log("WARNING: Could not register signal loggers: %s", e.getMessage());
        }
    }

    private ServiceInterface connected() {
        if (service == null) throw new IllegalStateException("Not connected. Click Connect first.");
        return service;
    }

    private SessionInterface connectedSession() {
        if (session == null) throw new IllegalStateException("Not connected. Click Connect first.");
        return session;
    }

    private CollectionInterface open() {
        if (collection == null) throw new IllegalStateException("No collection is open. Open one first.");
        return collection;
    }

    // -- Items --

    /** The path of the new item. */
    Optional<String> createItem(String label, CharSequence secret, Map<String, String> attributes) {
        Optional<String> path = open().createItem(label, secret, attributes.isEmpty() ? null : attributes);
        if (path.isPresent()) log("Created item: %s", path.get());
        else log("ERROR: createItem returned empty.");
        return path;
    }

    /** The paths of the collection's items. */
    List<String> listItems() {
        Optional<List<String>> items = open().getItems(Map.of());
        if (items.isPresent()) log("Listed %d item(s).", items.get().size());
        else log("Listed 0 item(s) (empty response).");
        return items.orElse(List.of());
    }

    /** The paths of the items that match. */
    List<String> search(String query, SearchMode mode, int maxDistance) {
        List<String> results = open().search(query, mode, maxDistance);
        int total = open().getItems(Map.of()).map(List::size).orElse(0);
        log("Search [%s] \"%s\": %d / %d item(s) matched.", mode, query, results.size(), total);
        return results;
    }

    /** The label and the attributes of the item. */
    ItemDetail detail(String path) {
        String label = open().getItemLabel(path).orElse("<unknown>");
        Map<String, String> attributes = new TreeMap<>(open().getAttributes(path).orElse(Map.of()));
        log("Selected item: %s (%s)", label, path);
        return new ItemDetail(path, label, attributes);
    }

    /** The secret of the item, which the caller erases. */
    Optional<char[]> readSecret(String path) {
        Optional<char[]> secret = open().getSecret(path);
        if (secret.isPresent()) log("Secret revealed for: %s", path);
        else log("Secret is empty for: %s", path);
        return secret;
    }

    boolean deleteItem(String path) {
        boolean deleted = open().deleteItem(path);
        if (deleted) log("Deleted item: %s", path);
        else log("WARNING: deleteItem returned false for: %s", path);
        return deleted;
    }

    /** Deletes the open collection, and closes it if the provider did. */
    boolean deleteCollection() {
        boolean deleted = open().delete();
        if (deleted) {
            log("Collection deleted.");
            closeCollection();
        } else {
            log("WARNING: collection.delete() returned false.");
        }
        return deleted;
    }

    // -- State --

    /** What the library's objects report now. */
    State state() {
        boolean busConnected = system != null && system.isConnected();
        String provider = service != null ? service.getProvider() : "N/A";
        return new State(busConnected, busConnected && service != null, provider,
                systemState(), serviceState(), sessionState(), collectionState());
    }

    private List<Row> systemState() {
        List<Row> rows = new ArrayList<>();
        rows.add(new Row("SystemInterface", system != null ? system.getClass().getSimpleName() : "null (not connected)"));
        rows.add(new Row("isConnected()", system != null ? str(system.isConnected()) : "N/A"));
        if (system != null) {
            DBusConnection connection = system.getConnection();
            rows.add(new Row("DBusConnection", connection != null ? connection.getClass().getSimpleName() : "null"));
            rows.add(new Row("DBusConnection.isConnected()", connection != null ? str(connection.isConnected()) : "N/A"));
            rows.add(new Row("DBusConnection.busAddress",
                    connection != null ? safe(() -> connection.getAddress().toString()) : "N/A"));
        }
        return rows;
    }

    private List<Row> serviceState() {
        if (service == null) return List.of(new Row("ServiceInterface", "null (not connected)"));
        List<Row> rows = new ArrayList<>();
        rows.add(new Row("ServiceInterface", service.getClass().getSimpleName()));
        rows.add(new Row("isGnomeKeyringAvailable()", safe(() -> service.isGnomeKeyringAvailable())));
        rows.add(new Row("getTimeout()", formatDuration(service.getTimeout())));
        rows.add(new Row("getSessions().size()", str(service.getSessions().size())));
        rows.add(new Row("getService()", service.getService() != null ? service.getService().getObjectPath() : "null"));
        return rows;
    }

    private List<Row> sessionState() {
        if (session == null) return List.of(new Row("SessionInterface", "null (not connected)"));
        List<Row> rows = new ArrayList<>();
        rows.add(new Row("SessionInterface", session.getClass().getSimpleName()));
        rows.add(new Row("getId()", str(session.getId())));
        rows.add(new Row("getSession().getObjectPath()",
                session.getSession() != null ? session.getSession().getObjectPath() : "null"));
        rows.add(new Row("getEncryptedSession()", session.getEncryptedSession() != null ? "present" : "null"));
        rows.add(new Row("getCollections().size()", safe(() -> session.getCollections().size())));
        return rows;
    }

    private List<Row> collectionState() {
        if (collection == null) return List.of(new Row("CollectionInterface", "null (not connected)"));
        List<Row> rows = new ArrayList<>();
        rows.add(new Row("CollectionInterface", collection.getClass().getSimpleName()));
        rows.add(new Row("getLabel()", safe(() -> collection.getLabel().orElse("<empty>"))));
        rows.add(new Row("getId()", safe(() -> collection.getId().orElse("<empty>"))));
        boolean locked = collection.isLocked();
        if (!locked) wasUnlockedOnce = true;
        rows.add(new Row("isLocked()", str(locked)));
        rows.add(new Row("wasUnlockedOnce", str(wasUnlockedOnce)));
        return rows;
    }

    private static String str(Object value) {
        return String.valueOf(value);
    }

    private static String formatDuration(Duration duration) {
        if (duration == null) return "null";
        return duration.getSeconds() + "s (" + duration.toMillis() + "ms)";
    }

    private static String safe(Callable<?> value) {
        try {
            return str(value.call());
        } catch (Exception e) {
            return "<error: " + e.getClass().getSimpleName() + ">";
        }
    }
}
