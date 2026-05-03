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
    private Logger log = LoggerFactory.getLogger(getClass());
    private DBusConnection connection = null;
    private String sourcePath = null;
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
        if (this.connection == null) {
            this.connection = connection;
        }
        this.sourcePath = sourcePath;
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
            List<S> signals = null;
            while (true) {
                if (Thread.currentThread().isInterrupted()) return null;
                Thread.sleep(DEFAULT_DELAY_MILLIS);
                current = getCount();
                if (current != last) {
                    signals = getHandledSignals(signal, path);
                    if (signals != null && !signals.isEmpty()) {
                        return signals.get(0);
                    }
                    last = current;
                }
            }
        });

        try {
            long start = System.nanoTime();
            long nanos = timeout.toNanos();
            while (!Thread.currentThread().isInterrupted()) {
                long now = System.nanoTime();
                if (handler.isDone()) {
                    return handler.get();
                } else if (now - start > nanos) {
                    throw new TimeoutException();
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

}
