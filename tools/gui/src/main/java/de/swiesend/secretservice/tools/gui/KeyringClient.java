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
import de.swiesend.secretservice.ProviderDetector;
import de.swiesend.secretservice.Static;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
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
    record Opened(String path, String label, String id, boolean isDefault, boolean locked) {
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

    /** The process that serves the Secret Service on the bus. */
    record Daemon(long pid, String command) {
    }

    /**
     * The items that a listing found, with the number of the collection's items and, for a search
     * or a filter, what it looked for.
     */
    record ItemListing(List<ItemRow> rows, int total, Optional<String> query) {
    }

    /**
     * An item of the open collection, as its properties tell it.
     *
     * @param locked empty where the provider does not say
     */
    record ItemRow(String path, String label, Map<String, String> attributes, Optional<Boolean> locked) {
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

    /** The label of an item whose properties the provider does not give. */
    static final String NOT_READABLE = "(not readable)";

    private final Consumer<String> log;
    private final List<AutoCloseable> signals = new ArrayList<>();

    private SystemInterface system;
    private ServiceInterface service;
    private SessionInterface session;
    private CollectionInterface collection;
    /** The object path of the open collection, which its items' signals name. */
    private String collectionPath;
    private volatile Runnable itemsChanged = () -> { };
    private volatile Runnable collectionsChanged = () -> { };
    private boolean wasUnlockedOnce = false;
    /** Whether the library may raise the provider's prompts, for each collection that opens. */
    private boolean prompting = true;
    /** How long the library waits for a prompt, for each connection; empty: the library's default. */
    private Optional<Duration> timeout = Optional.empty();

    /**
     * @param log takes the lines for the window's log, from any thread
     */
    KeyringClient(Consumer<String> log) {
        this.log = log;
    }

    /**
     * Takes what to run when the provider signals that an item of the open collection, or a
     * collection, was created, changed or deleted. They run on the bus's thread.
     */
    void onChanges(Runnable items, Runnable collections) {
        this.itemsChanged = items;
        this.collectionsChanged = collections;
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
            timeout.ifPresent(service::setTimeout);

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
                    new de.swiesend.secretservice.Collection(path, system.getConnection(), null);
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
                : connectedSession().collectionById(entry.id()), entry.path(), defaultAcknowledged);
    }

    /** The path of the collection that the {@code default} alias names, if it names one. */
    private Optional<String> defaultAlias() {
        return connected().getService().readAlias("default")
                .map(DBusPath::getPath)
                .filter(path -> !"/".equals(path));
    }

    /**
     * Creates a collection with that label and opens it: with the password, or through the
     * provider's dialog where it is empty. The library's {@code collection(label, ...)} opens a
     * collection that has the label instead of creating one; the client refuses a label that a
     * collection of the provider has, which opens from the list, a default one after the
     * acknowledgement of its risk.
     */
    OpenOutcome create(String label, CharSequence password) {
        if (listCollections().stream().anyMatch(entry -> entry.label().equals(label))) {
            log("Not created: a collection has the label \"%s\". Open it from the list.", label);
            return OpenOutcome.failed();
        }
        log("Creating collection: %s", label);
        Optional<CharSequence> maybePassword = password.length() == 0 ? Optional.empty() : Optional.of(password);
        Optional<CollectionInterface> created = connectedSession().collection(label, maybePassword);
        String path = created.flatMap(CollectionInterface::getId).map(Static.ObjectPaths::collection).orElse(null);
        return opened(created, path, false);
    }

    private OpenOutcome opened(Optional<CollectionInterface> maybeCollection, String path, boolean defaultAcknowledged) {
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
        collectionPath = path;
        if (!prompting) collection.disablePrompt();
        String label = collection.getLabel().orElse("?");
        String id = collection.getId().orElse("?");
        log("Connected to collection label=\"%s\" id=\"%s\"%s.", label, id, isDefault ? " (default)" : "");
        boolean locked = collection.isLocked();
        if (!locked) wasUnlockedOnce = true;
        log("Locked: %s", locked);
        return new OpenOutcome(Optional.of(new Opened(path, label, id, isDefault, locked)), false);
    }

    /** Closes the open collection, and keeps the session, as the user asked. */
    void close() {
        closeCollection();
        log("Closed the collection.");
    }

    /** Closes the open collection, and keeps the session. */
    void closeCollection() {
        if (collection != null) closeQuietly(collection);
        collection = null;
        collectionPath = null;
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
        collectionPath = null;
        system = null;
        wasUnlockedOnce = false;
    }

    private void registerSignalLoggers() {
        DBusConnection connection = system.getConnection();
        try {
            signals.add(connection.addSigHandler(CollectionCreated.class, s -> {
                log("> CollectionCreated(%s)", s.collection);
                collectionsChanged.run();
            }));
            signals.add(connection.addSigHandler(CollectionChanged.class, s -> {
                log("> CollectionChanged(%s)", s.collection);
                collectionsChanged.run();
            }));
            signals.add(connection.addSigHandler(CollectionDeleted.class, s -> {
                log("> CollectionDeleted(%s)", s.collection);
                collectionsChanged.run();
            }));
            signals.add(connection.addSigHandler(ItemCreated.class, s -> {
                log("> ItemCreated(%s) on %s", s.item, s.getPath());
                itemChanged(s.getPath());
            }));
            signals.add(connection.addSigHandler(ItemChanged.class, s -> {
                log("> ItemChanged(%s) on %s", s.item, s.getPath());
                itemChanged(s.getPath());
            }));
            signals.add(connection.addSigHandler(ItemDeleted.class, s -> {
                log("> ItemDeleted(%s) on %s", s.item, s.getPath());
                itemChanged(s.getPath());
            }));
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

    /** Passes on a signal of an item of the open collection, which names the collection. */
    private void itemChanged(String collection) {
        if (collection != null && collection.equals(collectionPath)) itemsChanged.run();
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

    /**
     * The collection's items, without a dialog of the provider: an unlocked collection lists them
     * through {@code getItems}, a locked one through its {@code Items} property, which needs no
     * unlock, and each row comes from the item's own properties, which need none either.
     */
    ItemListing listItems() {
        CollectionInterface open = open();
        boolean locked = open.isLocked();
        List<String> paths;
        if (locked) {
            paths = new de.swiesend.secretservice.Collection(new DBusPath(collectionPath), system.getConnection(), null)
                    .getItems()
                    .map(Static.Convert::toStrings)
                    .orElse(List.of());
            log("Listed %d item(s) of the locked collection, by their properties.", paths.size());
        } else {
            Optional<List<String>> items = open.getItems(Map.of());
            paths = items.orElse(List.of());
            if (items.isPresent()) log("Listed %d item(s).", paths.size());
            else log("Listed 0 item(s) (empty response).");
        }
        return new ItemListing(rows(paths), paths.size(), Optional.empty());
    }

    /** The items that match, which {@code search} lists after it unlocks the collection. */
    ItemListing search(String query, SearchMode mode, int maxDistance, String what) {
        List<String> results = open().search(query, mode, maxDistance);
        int total = open().getItems(Map.of()).map(List::size).orElse(0);
        log("Search [%s] \"%s\": %d / %d item(s) matched.", mode, query, results.size(), total);
        return new ItemListing(rows(results), total, Optional.of(what));
    }

    private List<ItemRow> rows(List<String> paths) {
        de.swiesend.secretservice.Service lowLevel = connected().getService();
        List<ItemRow> rows = new ArrayList<>();
        for (String path : paths) {
            Worker.checkCancelled();
            de.swiesend.secretservice.Item item = new de.swiesend.secretservice.Item(new DBusPath(path), lowLevel);
            rows.add(new ItemRow(path, item.getLabel().orElse(NOT_READABLE),
                    new TreeMap<>(item.getAttributes().orElse(Map.of())), item.lockedState()));
        }
        return rows;
    }

    /**
     * A copy of the item's secret, which the caller erases. The library erases its own array when
     * {@code withSecret} returns.
     */
    Optional<char[]> readSecret(String path) {
        Optional<char[]> secret = open().withSecret(path, char[]::clone);
        if (secret.isPresent()) log("Read the secret of: %s", path);
        else log("ERROR: Could not read the secret of: %s", path);
        return secret;
    }

    /**
     * Updates the item: a {@code null} label or secret stays as it is, and the attributes replace
     * the item's.
     */
    boolean updateItem(String path, String label, CharSequence secret, Map<String, String> attributes) {
        boolean updated = open().updateItem(path, label, secret, attributes);
        if (updated) log("Updated item: %s%s", path, secret != null ? " (with a new secret)" : "");
        else log("WARNING: updateItem returned false for: %s", path);
        return updated;
    }

    boolean lockItem(String path) {
        boolean locked = open().lockItem(path);
        log(locked ? "Locked item: %s" : "WARNING: lockItem returned false for: %s", path);
        return locked;
    }

    boolean unlockItem(String path) {
        boolean unlocked = open().unlockItem(path);
        log(unlocked ? "Unlocked item: %s" : "WARNING: unlockItem returned false for: %s", path);
        return unlocked;
    }

    /** Deletes the items, after the user's permission through the provider's dialog. */
    boolean deleteItems(List<String> paths) {
        boolean deleted = open().deleteItems(paths);
        if (deleted) log("Deleted %d item(s).", paths.size());
        else log("WARNING: deleteItems returned false for %d item(s).", paths.size());
        return deleted;
    }

    /** Locks the open collection. */
    boolean lockCollection() {
        boolean locked = open().lock();
        log(locked ? "Locked the collection." : "WARNING: lock returned false.");
        return locked;
    }

    /**
     * Unlocks the open collection through the provider's dialog, which the library raises also
     * where it knows the password: {@code unlockWithUserPermission}.
     */
    boolean unlockCollection() {
        boolean unlocked = open().unlockWithUserPermission();
        log(unlocked ? "Unlocked the collection." : "WARNING: unlockWithUserPermission returned false.");
        return unlocked;
    }

    /** Gives the open collection a new label. */
    boolean renameCollection(String label) {
        boolean renamed = open().setLabel(label);
        log(renamed ? "Renamed the collection." : "WARNING: setLabel returned false.");
        return renamed;
    }

    /**
     * Lets the library raise the provider's prompts, or keeps it from them: then the provider
     * alone decides what a call without a prompt may do. For the open collection and each one
     * that opens.
     */
    void setPrompting(boolean prompting) {
        this.prompting = prompting;
        if (collection != null) {
            if (prompting) collection.enablePrompt();
            else collection.disablePrompt();
        }
        log(prompting ? "Prompts are enabled." : "Prompts are disabled.");
    }

    /** How long the library waits for a prompt, for this connection and each that follows. */
    void setTimeout(Duration timeout) {
        this.timeout = Optional.of(timeout);
        if (service != null) service.setTimeout(timeout);
        log("The service's timeout is %d s.", timeout.getSeconds());
    }

    /** The items with exactly these attributes, through {@code getItems}, which unlocks first. */
    ItemListing filter(Map<String, String> attributes, String what) {
        List<String> paths = open().getItems(attributes).orElse(List.of());
        int total = open().getItems(Map.of()).map(List::size).orElse(0);
        log("Filter by %d attribute(s): %d item(s) matched.", attributes.size(), paths.size());
        return new ItemListing(rows(paths), total, Optional.of(what));
    }

    /**
     * Reads every secret of the collection through {@code withSecrets}, which asks the user's
     * permission, and tells only how many it read: the secrets stay in the callback.
     */
    Optional<Integer> readAllSecrets() {
        Optional<Integer> read = open().withSecrets(Map::size);
        if (read.isPresent()) log("Read the secrets of %d item(s).", read.get());
        else log("WARNING: withSecrets returned nothing.");
        return read;
    }

    /** Whether the open collection is locked now. */
    boolean isLocked() {
        return open().isLocked();
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

    // -- The provider's daemon --

    /** The command of gnome-keyring's daemon, the only one that the window stops. */
    static final String GNOME_KEYRING_DAEMON = "gnome-keyring-daemon";

    /**
     * Whether gnome-keyring serves the Secret Service. Other providers are applications of their
     * own, as KeePassXC, or parts of the desktop, as KWallet, which the window does not stop.
     */
    boolean isGnomeKeyring() {
        return service != null && service.detectProvider() == ProviderDetector.Provider.GNOME_KEYRING;
    }

    /**
     * The process that owns the Secret Service's name on this bus, as the bus tells it, where it is
     * gnome-keyring's daemon of this user: not any process of that name, as {@code pkill -f} took.
     */
    Optional<Daemon> providerDaemon() {
        if (!isGnomeKeyring()) {
            log("The provider is not gnome-keyring: the window stops only gnome-keyring's daemon.");
            return Optional.empty();
        }
        DBus bus;
        try {
            bus = system.getConnection().getRemoteObject("org.freedesktop.DBus", "/org/freedesktop/DBus", DBus.class);
        } catch (DBusException e) {
            log("ERROR: Could not reach the bus: %s", e.getMessage());
            return Optional.empty();
        }
        long pid = bus.GetConnectionUnixProcessID(Static.Service.SECRETS).longValue();
        Optional<ProcessHandle> process = ProcessHandle.of(pid);
        if (process.isEmpty()) {
            log("ERROR: The bus names process %d, which this user cannot see.", pid);
            return Optional.empty();
        }
        String command = process.get().info().command().orElse("?");
        String user = process.get().info().user().orElse("?");
        if (!Path.of(command).getFileName().toString().equals(GNOME_KEYRING_DAEMON)) {
            log("ERROR: Process %d serves the Secret Service, and is no %s but %s.", pid, GNOME_KEYRING_DAEMON, command);
            return Optional.empty();
        }
        if (!user.equals(System.getProperty("user.name"))) {
            log("ERROR: Process %d belongs to %s, not to this user.", pid, user);
            return Optional.empty();
        }
        return Optional.of(new Daemon(pid, command));
    }

    /**
     * Stops the daemon, which the user confirmed, and disconnects: the session ends with it. It
     * stops only that process, and only while it still is the daemon.
     *
     * @return whether the process has ended
     */
    boolean stop(Daemon daemon) throws InterruptedException {
        Optional<ProcessHandle> process = ProcessHandle.of(daemon.pid())
                .filter(handle -> handle.info().command().orElse("").equals(daemon.command()));
        if (process.isEmpty()) {
            log("Process %d is no longer %s.", daemon.pid(), daemon.command());
            disconnect();
            return false;
        }
        disconnect();
        boolean asked = process.get().destroy(); // SIGTERM, which gnome-keyring ends on
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!hasEnded(process.get())) {
            if (System.nanoTime() > deadline) {
                log("WARNING: Process %d has not ended within 5 s.", daemon.pid());
                return false;
            }
            Thread.sleep(100);
        }
        log("Stopped %s (process %d)%s.", daemon.command(), daemon.pid(), asked ? "" : ", which had ended");
        return true;
    }

    /**
     * Whether the process has ended. One that its parent has not reaped yet, a zombie, still
     * counts as alive for {@link ProcessHandle#isAlive()}, and has no command any more.
     */
    private static boolean hasEnded(ProcessHandle process) {
        return !process.isAlive() || process.info().command().isEmpty();
    }

    /**
     * Starts gnome-keyring's daemon for the Secret Service, where none serves it. Its output is
     * the environment of the daemon, which names no secret.
     *
     * @return the daemon's exit code
     */
    int startGnomeKeyring() throws IOException, InterruptedException {
        Process start = new ProcessBuilder(GNOME_KEYRING_DAEMON, "--start", "--components=secrets")
                .redirectErrorStream(true)
                .start();
        String output = new String(start.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        int exit = start.waitFor();
        log("%s --start: exit=%d %s", GNOME_KEYRING_DAEMON, exit, output);
        return exit;
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
