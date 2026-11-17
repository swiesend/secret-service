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
import org.freedesktop.dbus.connections.impl.DBusConnection;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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

    /** The collection that a connect opened. */
    record Opened(String label, String id, boolean locked) {
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

    /** Connects to the bus and opens the default collection. */
    Optional<Opened> connectToDefault() {
        return connect(() -> session.defaultCollection());
    }

    /** Connects to the bus and opens the collection with that id, the last element of its path. */
    Optional<Opened> connectById(String id) {
        return connect(() -> {
            log("Opening collection by id: %s", id);
            return session.collectionById(id);
        });
    }

    /**
     * Connects to the bus and opens the collection with that label, which the provider creates if
     * it has none.
     *
     * @param password the password of a collection that gnome-keyring creates
     */
    Optional<Opened> connectByLabel(String label, CharSequence password) {
        return connect(() -> {
            log("Opening collection by label: %s", label);
            return session.collection(label, Optional.of(password));
        });
    }

    private Optional<Opened> connect(Callable<Optional<CollectionInterface>> open) {
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
                system.disconnect();
                system = null;
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

            Optional<CollectionInterface> maybeCollection = open.call();
            if (maybeCollection.isEmpty()) {
                log("ERROR: Could not open collection.");
                disconnect();
                return Optional.empty();
            }
            collection = maybeCollection.get();
            String label = collection.getLabel().orElse("?");
            String id = collection.getId().orElse("?");
            log("Connected to collection label=\"%s\" id=\"%s\".", label, id);
            boolean locked = collection.isLocked();
            if (!locked) wasUnlockedOnce = true;
            log("Locked: %s", locked);
            return Optional.of(new Opened(label, id, locked));
        } catch (Exception e) {
            disconnect();
            throw e instanceof RuntimeException runtime ? runtime : new IllegalStateException(e);
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

    private CollectionInterface open() {
        if (collection == null) throw new IllegalStateException("Not connected. Click Connect first.");
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

    /** Deletes the open collection, and disconnects if the provider did. */
    boolean deleteCollection() {
        boolean deleted = open().delete();
        if (deleted) {
            log("Collection deleted.");
            disconnect();
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
