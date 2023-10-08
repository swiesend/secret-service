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
    private List<Class<? extends DBusSignal>> registered = new ArrayList<>();
    private DBusSignal[] handled = new DBusSignal[bufferSize];
    private int count = 0;

    public static SignalHandler getInstance() {
        return SingletonHelper.INSTANCE;
    }

    public void connect(DBusConnection connection, List<Class<? extends DBusSignal>> signals) {
        if (this.connection == null) {
            this.connection = connection;
        }
        if (signals != null) {
            try {
                for (Class sc : signals) {
                    if (!registered.contains(sc)) {
                        connection.addSigHandler(sc, this);
                        this.registered.add(sc);
                    }
                }
            } catch (DBusException e) {
                log.error("Could not connect to the D-Bus: ", e);
            } catch (ClassCastException e) {
                log.error("Could not cast a signal: ", e);
            }

        }
    }

    @Override
    public void handle(DBusSignal s) {

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
                .filter(signal -> signal.getPath().equals(path))
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
                Thread.currentThread().sleep(DEFAULT_DELAY_MILLIS);
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
                Thread.currentThread().sleep(DEFAULT_DELAY_MILLIS);
            }
        } catch (CancellationException | ExecutionException | InterruptedException | TimeoutException e) {
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

    private static class SingletonHelper {
        private static final SignalHandler INSTANCE = new SignalHandler();
    }
}
