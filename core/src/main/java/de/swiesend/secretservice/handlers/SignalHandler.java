package de.swiesend.secretservice.handlers;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBus;
import org.freedesktop.dbus.interfaces.DBusSigHandler;
import org.freedesktop.dbus.messages.DBusSignal;
import de.swiesend.secretservice.interfaces.Collection;
import de.swiesend.secretservice.interfaces.Prompt;
import de.swiesend.secretservice.interfaces.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import static de.swiesend.secretservice.Static.DBus.DEFAULT_DELAY_MILLIS;

public class SignalHandler implements DBusSigHandler {

    private final static int bufferSize = 1024;
    /** How often an await asks who owns the provider's name: every tenth of its ticks, once a second. */
    private static final int OWNER_CHECK_TICKS = 10;
    // Named for the declaring class, not getClass(); see MessageHandler for why.
    private static final Logger log = LoggerFactory.getLogger(SignalHandler.class);
    private DBusConnection connection = null;
    private String sourcePath = null;
    /** The bus name of the provider whose signals {@link #await} waits for, or null for any sender. */
    private String provider = null;
    private List<AutoCloseable> registrations = new ArrayList<>();
    private DBusSignal[] handled = new DBusSignal[bufferSize];
    private int count = 0;

    /**
     * Connect to D-Bus and register signal handlers, optionally scoped to a specific source path.
     * <p>
     * When a non-root {@code sourcePath} is provided, signals are only received from that D-Bus object path.
     * This prevents cross-talk between signal handlers of different collections or services.
     *
     * @param connection the D-Bus connection
     * @param signals    the signal classes to register for
     * @param sourcePath the D-Bus object path to scope signal reception to,
     *                   or {@code null}/{@code "/"} for global (unscoped) registration
     */
    public void connect(DBusConnection connection, List<Class<? extends DBusSignal>> signals, String sourcePath) {
        connect(connection, signals, sourcePath, null);
    }

    /**
     * As {@link #connect(DBusConnection, List, String)}, for the signals of {@code provider}, a bus
     * name such as {@code org.freedesktop.secrets}. {@link #await} then takes a signal only from the
     * unique name that owns {@code provider} when the wait begins, and ends the wait when another
     * name or none owns it.
     */
    public void connect(DBusConnection connection, List<Class<? extends DBusSignal>> signals, String sourcePath,
                        String provider) {
        if (this.connection == null) {
            this.connection = connection;
        }
        this.sourcePath = sourcePath;
        this.provider = provider;
        if (signals != null) {
            try {
                for (Class sc : signals) {
                    // Register signal handler without specifying a sender (the DBus API
                    // parameter is the sender/bus name, not the object path). We perform
                    // path-scoping in `handle()` to avoid InvalidBusNameException when
                    // a path-like string is provided.
                    AutoCloseable reg = connection.addSigHandler(sc, this);
                    registrations.add(reg);
                }
            } catch (DBusException e) {
                log.error("Could not connect to the D-Bus: ", e);
            } catch (ClassCastException e) {
                log.error("Could not cast a signal: ", e);
            }

        }
    }

    /**
     * Unregister all signal handlers and release resources.
     */
    public void disconnect() {
        for (AutoCloseable reg : registrations) {
            try {
                reg.close();
            } catch (Exception e) {
                log.warn("Could not unregister a signal handler: ", e);
            }
        }
        registrations.clear();
        synchronized (handled) {
            Arrays.fill(handled, null);
            count = 0;
        }
        connection = null;
        sourcePath = null;
        provider = null;
    }

    @Override
    public void handle(DBusSignal s) {
        // If a source path was provided during connect(), ignore signals that
        // do not originate from that object path. This provides the path-scoped
        // semantics we want while using the global DBus addSigHandler registration.
        if (this.sourcePath != null && !"/".equals(this.sourcePath)) {
            try {
                if (!this.sourcePath.equals(s.getPath())) {
                    return; // ignore signals from other object paths
                }
            } catch (Exception e) {
                // In case s.getPath() throws or is null, fall through and handle
            }
        }

        synchronized (handled) {
            Collections.rotate(Arrays.asList(handled), 1);
            handled[0] = s;
            count++;
        }

        if (s instanceof Collection.ItemCreated) {
            Collection.ItemCreated ic = (Collection.ItemCreated) s;
            log.info("Received signal: Collection.ItemCreated(" + ic.item + ")");
        } else if (s instanceof Collection.ItemChanged) {
            Collection.ItemChanged ic = (Collection.ItemChanged) s;
            log.debug("Received signal: Collection.ItemChanged(" + ic.item + ")");
        } else if (s instanceof Collection.ItemDeleted) {
            Collection.ItemDeleted ic = (Collection.ItemDeleted) s;
            log.info("Received signal: Collection.ItemDeleted(" + ic.item + ")");
        } else if (s instanceof Prompt.Completed) {
            Prompt.Completed c = (Prompt.Completed) s;
            log.info("Received signal: Prompt.Completed(" + s.getPath() + "): {dismissed: " + c.dismissed + ", result: " + c.result + "}");
        } else if (s instanceof Service.CollectionCreated) {
            Service.CollectionCreated cc = (Service.CollectionCreated) s;
            log.info("Received signal: Service.CollectionCreated(" + cc.collection + ")");
        } else if (s instanceof Service.CollectionChanged) {
            Service.CollectionChanged cc = (Service.CollectionChanged) s;
            log.info("Received signal: Service.CollectionChanged(" + cc.collection + ")");
        } else if (s instanceof Service.CollectionDeleted) {
            Service.CollectionDeleted cc = (Service.CollectionDeleted) s;
            log.info("Received signal: Service.CollectionDeleted(" + cc.collection + ")");
        } else try {
            log.warn("Received unexpected signal: " + s.getClass().getName() + ": {" + s + "}");
        } catch (NullPointerException e) {
            log.warn("Received unknown signal.");
        }

    }

    public DBusSignal[] getHandled() {
        return handled;
    }

    public <S extends DBusSignal> List<S> getHandledSignals(Class<S> s) {
        return Arrays.stream(handled)
                .filter(signal -> signal != null)
                .filter(signal -> signal.getClass().equals(s))
                .map(signal -> (S) signal)
                .collect(Collectors.toList());
    }

    public <S extends DBusSignal> List<S> getHandledSignals(Class<S> s, String path) {
        return Arrays.stream(handled)
                .filter(signal -> signal != null)
                .filter(signal -> signal.getClass().equals(s))
                .filter(signal -> {
                    String sigPath = signal.getPath();
                    if (path == null || "/".equals(path)) return true;
                    if (sigPath == null) return false;
                    if (sigPath.equals(path)) return true;
                    // Item signals may be emitted with the item's object path
                    // (e.g. /org/freedesktop/secrets/collection/<id>/<item>). Accept
                    // signals that start with the requested collection path + '/'.
                    return sigPath.startsWith(path + "/");
                })
                .map(signal -> (S) signal)
                .collect(Collectors.toList());
    }

    public int getCount() {
        return count;
    }

    public DBusSignal getLastHandledSignal() {
        return handled[0];
    }

    public <S extends DBusSignal> S getLastHandledSignal(Class<S> s) {
        List<S> signals = getHandledSignals(s);
        if (signals != null && !signals.isEmpty()) {
            return signals.get(0);
        } else {
            return null;
        }
    }

    public <S extends DBusSignal> S getLastHandledSignal(Class<S> s, String path) {
        List<S> signals = getHandledSignals(s, path);
        if (signals != null && !signals.isEmpty()) {
            return signals.get(0);
        } else {
            return null;
        }
    }

    public <S extends DBusSignal> S await(Class<S> signal, String path, Callable action, Duration timeout) {
        final int init = count;
        // Only the provider answers its prompt. Any client on the bus can send a Completed signal
        // for the prompt's path, a refusal or a consent, and createItem takes the new item's path
        // from a signal. The provider's unique name is read before the prompt is shown; where it
        // cannot be read, any sender counts, as before.
        final String owner = ownerOf(provider);

        Optional<Prompt> maybePrompt = Optional.empty();
        try {
            maybePrompt = Optional.ofNullable((Prompt) action.call());
        } catch (Exception e) {
            log.error("Could not acquire a prompt.", e);
        }

        try {
            log.info("Await signal {}.{}({}) within {} seconds.",
                    signal.getEnclosingClass().getSimpleName(),
                    signal.getSimpleName(),
                    path,
                    timeout.getSeconds());
        } catch (NullPointerException e) {
            log.error("Await signal for unknown class.");
        }

        ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "secret-service:signal-handler");
            thread.setDaemon(true);
            return thread;
        });

        final Future<S> handler = executor.submit((Callable) () -> {
            int current = init;
            int last = init;
            List<S> signals = null;
            while (true) {
                if (Thread.currentThread().isInterrupted()) return null;
                Thread.sleep(DEFAULT_DELAY_MILLIS);
                current = getCount();
                if (current != last) {
                    signals = getHandledSignals(signal, path).stream()
                            .filter(received -> owner == null || owner.equals(received.getSource()))
                            .collect(Collectors.toList());
                    if (!signals.isEmpty()) {
                        return signals.get(0);
                    }
                    last = current;
                }
            }
        });

        try {
            long start = System.nanoTime();
            long nanos = timeout.toNanos();
            int ticks = 0;
            while (!Thread.currentThread().isInterrupted()) {
                long now = System.nanoTime();
                if (handler.isDone()) {
                    return handler.get();
                } else if (now - start > nanos) {
                    throw new TimeoutException();
                }
                // Nothing answers once the connection has closed or the provider has left the bus,
                // and there is no prompt left to dismiss.
                if (connection == null || !connection.isConnected()) {
                    log.warn("Stopped waiting for the prompt ({}): the connection closed.", path);
                    return null;
                }
                if (owner != null && ++ticks % OWNER_CHECK_TICKS == 0 && !owner.equals(ownerOf(provider))) {
                    log.warn("Stopped waiting for the prompt ({}): the provider left the bus.", path);
                    return null;
                }
                Thread.sleep(DEFAULT_DELAY_MILLIS);
            }
        } catch (CancellationException | ExecutionException | InterruptedException | TimeoutException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            maybePrompt.ifPresentOrElse(
                    (prompt) -> {
                        prompt.dismiss();
                        log.warn("Cancelled the prompt (" + path + ") manually after exceeding the timeout of " + timeout.getSeconds() + " seconds.");
                    },
                    () -> {
                        log.warn("Cancelled the action, but could not dismiss the prompt.", e);
                    });
        } finally {
            handler.cancel(true);
            executor.shutdownNow();
        }

        return null;
    }

    /**
     * The unique name that owns {@code name} on the bus now, or null when no one does or it cannot
     * be read. GetNameOwner answers NameHasNoOwner for a name that no one owns.
     */
    private String ownerOf(String name) {
        DBusConnection c = connection;
        if (name == null || c == null) return null;
        try {
            DBus bus = c.getRemoteObject("org.freedesktop.DBus", "/org/freedesktop/DBus", DBus.class);
            return bus.GetNameOwner(name);
        } catch (DBusException | RuntimeException e) {
            return null;
        }
    }

}
