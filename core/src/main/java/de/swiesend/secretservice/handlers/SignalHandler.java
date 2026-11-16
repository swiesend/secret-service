package de.swiesend.secretservice.handlers;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
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
    /** How often an await looks after the provider's owner: every tenth of its ticks, once a second. */
    private static final int OWNER_CHECK_TICKS = 10;
    private Logger log = LoggerFactory.getLogger(getClass());
    // connection and sourcePath change under the lock on the buffer, and with it: a signal counts
    // for the connection and the path that the buffer is kept for.
    private volatile DBusConnection connection = null;
    private volatile String sourcePath = null;
    /** Who owns the bus name of the provider whose signals this handler takes, or null for any sender's. */
    private volatile BusNameOwner provider = null;
    private List<AutoCloseable> registrations = new ArrayList<>();
    /** The signals taken, the newest first. Read and written under its own lock, as {@link #count}. */
    private final DBusSignal[] handled = new DBusSignal[bufferSize];
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
    /**
     * Held while the library adds or removes a signal handler. dbus-java 5.2.0 removes a signal's
     * match rule once its last handler is gone, and a handler that is added meanwhile for the same
     * signal joins the queue that goes, without a match rule of its own: it never gets a signal.
     */
    private static final Object REGISTRATION = new Object();

    /**
     * Adds {@code handler} for {@code type} on {@code connection}, as
     * {@link DBusConnection#addSigHandler(Class, DBusSigHandler)} does, and removes it on
     * {@code close()}, both under the lock that the library's other handlers are added and removed
     * under.
     */
    public static <T extends DBusSignal> AutoCloseable addSigHandler(DBusConnection connection, Class<T> type,
                                                                     DBusSigHandler<T> handler) throws DBusException {
        AutoCloseable registration;
        synchronized (REGISTRATION) {
            registration = connection.addSigHandler(type, handler);
        }
        return () -> {
            synchronized (REGISTRATION) {
                registration.close();
            }
        };
    }

    public void connect(DBusConnection connection, List<Class<? extends DBusSignal>> signals, String sourcePath) {
        connect(connection, signals, sourcePath, null);
    }

    /**
     * As {@link #connect(DBusConnection, List, String)}, for the signals of {@code provider} only, a
     * bus name such as {@code org.freedesktop.secrets}.
     * <p>
     * A signal's match rule names no sender, and any client on the bus can send a signal for any
     * path: a {@code Completed} that answers a prompt with a consent or a refusal, or an
     * {@code ItemCreated} that names an item. With a {@code provider}, this handler takes a signal
     * only from the unique name that owns that bus name, and none while nobody owns it or the owner
     * cannot be read. It follows the owner through the bus's {@code NameOwnerChanged}, see
     * {@link BusNameOwner}: a signal costs no call to the bus.
     *
     * @param provider the bus name whose owner's signals count, or {@code null} for any sender's
     */
    public void connect(DBusConnection connection, List<Class<? extends DBusSignal>> signals, String sourcePath,
                        String provider) {
        // Before the lock, which the thread that dispatches the signals takes: this may ask the bus.
        final BusNameOwner name = provider == null ? null : BusNameOwner.of(connection, provider);
        synchronized (handled) {
            if (this.connection == null) {
                this.connection = connection;
            }
            this.sourcePath = sourcePath;
            this.provider = name;
        }
        if (signals != null) {
            try {
                for (Class sc : signals) {
                    // Register signal handler without specifying a sender (the DBus API
                    // parameter is the sender/bus name, not the object path). We perform
                    // path-scoping in `handle()` to avoid InvalidBusNameException when
                    // a path-like string is provided.
                    AutoCloseable reg = addSigHandler(connection, sc, this);
                    registrations.add(reg);
                }
            } catch (DBusException e) {
                log.error("Could not connect to the D-Bus: ", e);
            } catch (ClassCastException e) {
                log.error("Could not cast a signal: ", e);
            }

        }
    }

    /** Whether this handler is registered on a connection: from {@link #connect} to {@link #disconnect()}. */
    public boolean isConnected() {
        return connection != null;
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
            connection = null;
            sourcePath = null;
            provider = null;
        }
    }

    /**
     * Whether the provider sent {@code s}: always, where {@link #connect} named none. On the thread
     * that dispatches the signals, so without a call to the bus: any client can send signals in
     * any number, and each call would hold up the provider's own.
     */
    private boolean sentByProvider(DBusSignal s) {
        final BusNameOwner name = provider;
        return name == null || name.isOwner(s.getSource());
    }

    @Override
    public void handle(DBusSignal s) {
        // If a source path was provided during connect(), ignore signals that
        // do not originate from that object path. This provides the path-scoped
        // semantics we want while using the global DBus addSigHandler registration.
        final String scope = this.sourcePath;
        if (scope != null && !"/".equals(scope)) {
            try {
                if (!scope.equals(s.getPath())) {
                    return; // ignore signals from other object paths
                }
            } catch (Exception e) {
                // In case s.getPath() throws or is null, fall through and handle
            }
        }

        // Only the provider's signals: a prompt's answer and a created item's path are taken from
        // them, and any client on the bus can send one.
        if (!sentByProvider(s)) {
            log.debug("Ignored a signal that the provider did not send, from {}.", s.getSource());
            return;
        }

        synchronized (handled) {
            // dbus-java can deliver a signal after its handler was removed. One that was on its
            // way while disconnect() ran, or while connect() gave this handler another path, was
            // checked against a path that no longer holds, or against none.
            if (connection == null || !Objects.equals(scope, sourcePath)) {
                return;
            }
            Collections.rotate(Arrays.asList(handled), 1);
            handled[0] = s;
            count++;
        }

        // DEBUG, not INFO: the service's and the prompt's handlers receive these signals for every
        // application on the bus, and on gnome-keyring a collection's object path is derived from
        // its label.
        if (s instanceof Collection.ItemCreated) {
            Collection.ItemCreated ic = (Collection.ItemCreated) s;
            log.debug("Received signal: Collection.ItemCreated({})", ic.item);
        } else if (s instanceof Collection.ItemChanged) {
            Collection.ItemChanged ic = (Collection.ItemChanged) s;
            log.debug("Received signal: Collection.ItemChanged({})", ic.item);
        } else if (s instanceof Collection.ItemDeleted) {
            Collection.ItemDeleted ic = (Collection.ItemDeleted) s;
            log.debug("Received signal: Collection.ItemDeleted({})", ic.item);
        } else if (s instanceof Prompt.Completed) {
            Prompt.Completed c = (Prompt.Completed) s;
            log.debug("Received signal: Prompt.Completed({}): {dismissed: {}, result: {}}", s.getPath(), c.dismissed, c.result);
        } else if (s instanceof Service.CollectionCreated) {
            Service.CollectionCreated cc = (Service.CollectionCreated) s;
            log.debug("Received signal: Service.CollectionCreated({})", cc.collection);
        } else if (s instanceof Service.CollectionChanged) {
            Service.CollectionChanged cc = (Service.CollectionChanged) s;
            log.debug("Received signal: Service.CollectionChanged({})", cc.collection);
        } else if (s instanceof Service.CollectionDeleted) {
            Service.CollectionDeleted cc = (Service.CollectionDeleted) s;
            log.debug("Received signal: Service.CollectionDeleted({})", cc.collection);
        } else try {
            log.warn("Received unexpected signal: " + s.getClass().getName() + ": {" + s + "}");
        } catch (NullPointerException e) {
            log.warn("Received unknown signal.");
        }

    }

    /**
     * The signals taken, the newest first, and null where the buffer is not filled: a copy, as the
     * buffer changes with every signal, on another thread.
     */
    public DBusSignal[] getHandled() {
        synchronized (handled) {
            return handled.clone();
        }
    }

    public <S extends DBusSignal> List<S> getHandledSignals(Class<S> s) {
        return Arrays.stream(getHandled())
                .filter(signal -> signal != null)
                .filter(signal -> signal.getClass().equals(s))
                .map(signal -> (S) signal)
                .collect(Collectors.toList());
    }

    public <S extends DBusSignal> List<S> getHandledSignals(Class<S> s, String path) {
        return Arrays.stream(getHandled())
                .filter(signal -> signal != null)
                .filter(signal -> signal.getClass().equals(s))
                .filter(signal -> isOnPath(signal, path))
                .map(signal -> (S) signal)
                .collect(Collectors.toList());
    }

    private static boolean isOnPath(DBusSignal signal, String path) {
        String sigPath = signal.getPath();
        if (path == null || "/".equals(path)) return true;
        if (sigPath == null) return false;
        if (sigPath.equals(path)) return true;
        // Item signals may be emitted with the item's object path
        // (e.g. /org/freedesktop/secrets/collection/<id>/<item>). Accept
        // signals that start with the requested collection path + '/'.
        return sigPath.startsWith(path + "/");
    }

    /**
     * The newest signal of class {@code s} on {@code path} among those handled after the first
     * {@code since}, or null. The buffer holds the newest signal first.
     */
    @SuppressWarnings("unchecked")
    private <S extends DBusSignal> S newestSince(int since, Class<S> s, String path) {
        synchronized (handled) {
            int fresh = Math.min(count - since, bufferSize);
            for (int i = 0; i < fresh; i++) {
                DBusSignal signal = handled[i];
                if (signal != null && signal.getClass().equals(s) && isOnPath(signal, path)) {
                    return (S) signal;
                }
            }
            return null;
        }
    }

    public int getCount() {
        synchronized (handled) {
            return count;
        }
    }

    public DBusSignal getLastHandledSignal() {
        synchronized (handled) {
            return handled[0];
        }
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

    /**
     * {@code timeout} in nanoseconds: none for a negative one, and at most {@link Long#MAX_VALUE},
     * some 292 years, where {@link Duration#toNanos()} would overflow.
     */
    private static long nanos(Duration timeout) {
        if (timeout.isNegative()) return 0;
        try {
            return timeout.toNanos();
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
        }
    }

    public <S extends DBusSignal> S await(Class<S> signal, String path, Callable action, Duration timeout) {
        // Before the action, which shows the prompt: it would wait for an answer that nobody collects.
        Objects.requireNonNull(timeout, "timeout must not be null");
        // On the caller's thread, where an owner that could not be read before is read again.
        // Only this name can answer: the wait ends when it has left the bus.
        final BusNameOwner name = provider;
        final String answers = name == null ? null : name.read().orElse(null);
        final DBusConnection waitsOn = connection;
        final int init = getCount();

        Optional<Prompt> maybePrompt = Optional.empty();
        try {
            maybePrompt = Optional.ofNullable((Prompt) action.call());
        } catch (Exception e) {
            log.error("Could not acquire a prompt.", e);
        }

        try {
            log.info(String.format("Await signal %s.%s(%s) within %d seconds.",
                    signal.getEnclosingClass().getSimpleName(),
                    signal.getSimpleName(),
                    path,
                    timeout.getSeconds()));
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
            while (true) {
                if (Thread.currentThread().isInterrupted()) return null;
                Thread.sleep(DEFAULT_DELAY_MILLIS);
                current = getCount();
                if (current != last) {
                    // Only what arrived since the await began: an older signal on the same path
                    // answered an earlier operation, perhaps one the user refused.
                    S received = newestSince(init, signal, path);
                    if (received != null) {
                        return received;
                    }
                    last = current;
                }
            }
        });

        S received = null;
        String gaveUp = "it was interrupted";
        // Once the connection has closed or the provider has left the bus, nothing answers, and
        // there is no prompt left to dismiss.
        boolean unanswerable = false;
        try {
            long start = System.nanoTime();
            long nanos = nanos(timeout);
            int ticks = 0;
            while (!Thread.currentThread().isInterrupted()) {
                long now = System.nanoTime();
                if (handler.isDone()) {
                    received = handler.get();
                    break;
                } else if (now - start > nanos) {
                    gaveUp = "it exceeded the timeout of " + timeout.getSeconds() + " seconds";
                    break;
                } else if (waitsOn != null && !waitsOn.isConnected()) {
                    gaveUp = "the connection closed";
                    unanswerable = true;
                    break;
                } else if (name != null && name.hasLost(answers)) {
                    gaveUp = "the provider left the bus";
                    unanswerable = true;
                    break;
                }
                // Asks the bus only where the owner's changes are not followed.
                if (name != null && ++ticks % OWNER_CHECK_TICKS == 0) name.read();
                Thread.sleep(DEFAULT_DELAY_MILLIS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (CancellationException | ExecutionException e) {
            gaveUp = "waiting failed: " + e;
        } finally {
            handler.cancel(true);
            executor.shutdownNow();
        }

        if (received == null) {
            // A last look before giving up: the answer may have arrived since the buffer was last
            // read, as from a provider that answers and leaves the bus at once.
            received = newestSince(init, signal, path);
        }
        if (received == null && unanswerable) {
            log.warn("Stopped waiting for the signal ({}) because {}.", path, gaveUp);
        } else if (received == null) {
            // Timed out or interrupted, also before the wait began: a prompt still open would
            // wait for an answer that nobody collects.
            final String reason = gaveUp;
            maybePrompt.ifPresentOrElse(
                    (prompt) -> {
                        prompt.dismiss();
                        log.warn("Cancelled the prompt ({}) because {}.", path, reason);
                    },
                    // The caller reports the missing signal, as createItem does.
                    () -> log.debug("Stopped waiting for the signal because {}.", reason));
        }
        return received;
    }

}
