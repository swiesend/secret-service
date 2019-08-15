package org.freedesktop.secret.handlers;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusSigHandler;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.secret.interfaces.Collection;
import org.freedesktop.secret.interfaces.Prompt;
import org.freedesktop.secret.interfaces.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class SignalHandler implements DBusSigHandler {

    private Logger log = LoggerFactory.getLogger(getClass());

    private DBusConnection connection = null;
    private List<Class<? extends DBusSignal>> registered = new ArrayList();
    private DBusSignal[] handled = new DBusSignal[250];
    private int count = 0;

    private SignalHandler() {
        Runtime.getRuntime().addShutdownHook(new Thread(() ->
                disconnect()
        ));
    }

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
                log.error(e.toString(), e.getCause());
            }
        }
    }

    public void disconnect() {
        if (connection != null) {
            try {
                log.debug("remove signal handlers");
                for (Class sc : registered) {
                    if (connection.isConnected()) {
                        log.trace("remove signal handler: " + sc.getName());
                        connection.removeSigHandler(sc, this);
                    }
                }
            } catch (DBusException e) {
                log.error(e.toString(), e.getCause());
            }
        }
    }

    @Override
    public void handle(DBusSignal s) {

        Collections.rotate(Arrays.asList(handled), 1);
        handled[0] = s;
        count += 1;

        if (s instanceof Collection.ItemCreated) {
            Collection.ItemCreated ic = (Collection.ItemCreated) s;
            log.info("Collection.ItemCreated: " + ic.item);
        } else if (s instanceof Collection.ItemChanged) {
            Collection.ItemChanged ic = (Collection.ItemChanged) s;
            log.info("Collection.ItemChanged: " + ic.item);
        } else if (s instanceof Collection.ItemDeleted) {
            Collection.ItemDeleted ic = (Collection.ItemDeleted) s;
            log.info("Collection.ItemDeleted: " + ic.item);
        } else if (s instanceof Prompt.Completed) {
            Prompt.Completed c = (Prompt.Completed) s;
            log.info("Prompt.Completed (" + s.getPath() + "): {dismissed: " + c.dismissed + ", result: " + c.result + "}");
        } else if (s instanceof Service.CollectionCreated) {
            Service.CollectionCreated cc = (Service.CollectionCreated) s;
            log.info("Service.CollectionCreated: " + cc.collection);
        } else if (s instanceof Service.CollectionChanged) {
            Service.CollectionChanged cc = (Service.CollectionChanged) s;
            log.info("Service.CollectionChanged: " + cc.collection);
        } else if (s instanceof Service.CollectionDeleted) {
            Service.CollectionDeleted cc = (Service.CollectionDeleted) s;
            log.info("Service.CollectionDeleted: " + cc.collection);
        } else {
            log.warn("Handled unknown signal: " + s.getClass().toString() + " {" + s.toString() + "}");
        }
    }

    public DBusSignal[] getHandledSignals() {
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

    public Optional<DBusSignal> getLastHandledSignal() {
        return Optional.ofNullable(handled[0]);
    }

    public <S extends DBusSignal> Optional<S> getLastHandledSignal(Class<S> s) {
        try {
            return Optional.ofNullable(getHandledSignals(s).get(0));
        } catch (NullPointerException | IndexOutOfBoundsException e) {
            return Optional.empty();
        }
    }

    public <S extends DBusSignal> Optional<S> getLastHandledSignal(Class<S> s, String path) {
        try {
            return Optional.ofNullable(getHandledSignals(s, path).get(0));
        } catch (NullPointerException | IndexOutOfBoundsException e) {
            return Optional.empty();
        }
    }

    public <S extends DBusSignal> Optional<S> await(Class<S> s, String path, Callable action) {
        final Duration timeout = Duration.ofSeconds(300);
        return await(s, path, action, timeout);
    }

    public <S extends DBusSignal> Optional<S> await(Class<S> s, String path, Callable action, Duration timeout) {

        try {
            action.call();
        } catch (Exception e) {
            log.error(e.toString(), e.getCause());
        }

        int init = getHandledSignals(s, path).size();
        ExecutorService executor = Executors.newSingleThreadExecutor();

        log.info("await signal " + s.getName() + "(" + path + ") within " + timeout.getSeconds() + " seconds.");

        final Future<S> handler = executor.submit((Callable) () -> {
            int await = init;
            List<S> signals = null;
            while (await == init) {
                Thread.sleep(50L);
                signals = getHandledSignals(s, path);
                await = signals.size();
            }
            if (!signals.isEmpty()) {
                return signals.get(0);
            } else {
                return null;
            }
        });

        try {
            return Optional.ofNullable(handler.get(timeout.toMillis(), TimeUnit.MILLISECONDS));
        } catch (TimeoutException | InterruptedException | ExecutionException e) {
            handler.cancel(true);
            log.error(e.toString(), e.getCause());
            return Optional.empty();
        } finally {
            executor.shutdownNow();
        }
    }

    private static class SingletonHelper {
        private static final SignalHandler INSTANCE = new SignalHandler();
    }

}
