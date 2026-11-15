package de.swiesend.secretservice.handlers;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.WeakHashMap;

/**
 * Who owns a bus name, such as {@code org.freedesktop.secrets}, on a connection: the unique name
 * of the provider, by which its signals are told from those of any other client on the bus.
 *
 * <p>One per connection and name, shared by all that ask. The bus announces every change of a
 * name's owner with {@code NameOwnerChanged}, and this class follows it: {@link #isOwner} asks the
 * bus nothing, and so may be called on the thread that dispatches the connection's signals, which a
 * call to the bus would hold up for every handler. A provider that starts again is known by its new
 * name as soon as the bus has said so.</p>
 *
 * <p>Fails closed: while the owner is not known, no name is the owner.</p>
 */
public final class BusNameOwner {

    private static final Logger log = LoggerFactory.getLogger(BusNameOwner.class);

    private static final String BUS_NAME = "org.freedesktop.DBus";
    private static final String BUS_PATH = "/org/freedesktop/DBus";

    /** Weak: a tracker holds its connection weakly, and the connection's handler holds the tracker. */
    private static final Map<DBusConnection, Map<String, BusNameOwner>> BY_CONNECTION = new WeakHashMap<>();

    private final WeakReference<DBusConnection> connection;
    private final String name;
    /** Whether the bus's {@code NameOwnerChanged} reaches this tracker; without it every {@link #read} asks. */
    private final boolean following;
    /** The owner's unique name, or null where nobody owns the name; valid while {@link #known}. */
    private volatile String owner = null;
    private volatile boolean known = false;
    /** How many changes the bus announced; guarded by this. A read that one overtook is dropped. */
    private long announced = 0;

    private BusNameOwner(DBusConnection connection, String name) {
        this.connection = new WeakReference<>(connection);
        this.name = name;
        boolean registered = false;
        try {
            // Before the first read, so that no change between the two is lost. It stays for the
            // connection's lifetime.
            SignalHandler.addSigHandler(connection, DBus.NameOwnerChanged.class, this::changed);
            registered = true;
        } catch (DBusException | RuntimeException e) {
            log.warn("Cannot follow who owns a bus name; it is read from the bus instead.", e);
        }
        this.following = registered;
    }

    /** The tracker of {@code name} on {@code connection}, which has read the owner once. */
    public static BusNameOwner of(DBusConnection connection, String name) {
        BusNameOwner tracker;
        boolean created = false;
        synchronized (BY_CONNECTION) {
            Map<String, BusNameOwner> byName = BY_CONNECTION.computeIfAbsent(connection, c -> new HashMap<>());
            tracker = byName.get(name);
            if (tracker == null) {
                tracker = new BusNameOwner(connection, name);
                byName.put(name, tracker);
                created = true;
            }
        }
        // Outside the lock: a call to the bus.
        if (created) tracker.read();
        return tracker;
    }

    /**
     * Whether {@code uniqueName} owns the name, as far as this tracker knows. Asks the bus
     * nothing.
     */
    public boolean isOwner(String uniqueName) {
        return uniqueName != null && known && uniqueName.equals(owner);
    }

    /**
     * The owner's unique name, or empty where nobody owns the name or it cannot be read. Asks the
     * bus where the owner is not known, or its changes are not followed: not for the thread that
     * dispatches the signals.
     */
    public Optional<String> read() {
        if (following && known) return Optional.ofNullable(owner);
        final long before;
        synchronized (this) {
            before = announced;
        }
        String read = null;
        boolean answered = false;
        DBusConnection c = connection.get();
        if (c != null) {
            try {
                read = c.getRemoteObject(BUS_NAME, BUS_PATH, DBus.class).GetNameOwner(name);
                answered = true;
            } catch (DBusException | RuntimeException e) {
                // NameHasNoOwner too: the bus announces the next owner, or the next read asks again.
                log.debug("Could not read who owns the bus name {}.", name, e);
            }
        }
        synchronized (this) {
            // What the bus announced meanwhile is newer than this answer.
            if (announced == before) {
                owner = answered ? read : null;
                known = answered;
            }
            return known ? Optional.ofNullable(owner) : Optional.empty();
        }
    }

    /**
     * Takes the new owner from the bus. Any client can send a signal by this name; only the bus
     * itself sends as {@code org.freedesktop.DBus}.
     */
    private void changed(DBus.NameOwnerChanged signal) {
        if (!name.equals(signal.name)) return;
        if (!BUS_NAME.equals(signal.getSource())) {
            log.warn("Ignored a NameOwnerChanged that the bus did not send, from {}.", signal.getSource());
            return;
        }
        synchronized (this) {
            announced++;
            owner = signal.newOwner == null || signal.newOwner.isEmpty() ? null : signal.newOwner;
            known = true;
        }
    }
}
