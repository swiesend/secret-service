package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.Pair;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.Service;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

/**
 * The unlock prompts of gnome-keyring that a connection has shown and that have no answer yet, one
 * per collection.
 *
 * <p>The library leaves such a prompt open when nobody answers it in time, as gnome-keyring aborts
 * where a client dismisses one (see {@link Prompt#await}). An unlock of the same collection on the
 * same connection then waits on that prompt instead of asking again. Asked again, gnome-keyring
 * queues another prompt behind the open dialog, and when the user cancels that dialog it brings up
 * one more for each request that the application has given up on. So one dialog serves all the
 * requests, and a single cancel refuses them all.</p>
 *
 * <p>Per connection, as gnome-keyring sends a prompt's {@code Completed} to the connection that
 * showed it, and as {@code SimpleCollection}'s instances share one connection: an application that
 * opens one per call, as Cryptomator does, makes its requests through several. The prompts end with
 * their {@code Completed} signal, which this class receives itself, so that none goes amiss
 * between two requests. A gnome-keyring that has started again since has none of them.</p>
 */
final class UnlockPrompts {

    private static final Logger log = LoggerFactory.getLogger(UnlockPrompts.class);

    /** Weak: the registration's handler holds its registry, not the connection. */
    private static final Map<DBusConnection, UnlockPrompts> BY_CONNECTION = new WeakHashMap<>();

    /** How often a wait on a prompt reads whether its collection is unlocked. */
    private static final Duration LOCK_CHECK = Duration.ofSeconds(1);

    /** How an unlock through gnome-keyring's dialog went; the provider's Locked state is the authority. */
    enum Unlock {
        /** gnome-keyring unlocked at once, the user answered the dialog, or the collection was unlocked meanwhile. */
        DONE,
        /** The user cancelled the dialog. */
        REFUSED,
        /** Nobody answered within the timeout, the wait was interrupted, or the call failed. */
        NO_ANSWER
    }

    /** A prompt that the connection showed, and the collection it unlocks. */
    private static final class Open {
        final String prompt;
        final String collection;
        /** The unique name that served the secrets when the prompt was given. */
        final String provider;
        final CompletableFuture<Prompt.Completed> completed = new CompletableFuture<>();

        Open(String prompt, String collection, String provider) {
            this.prompt = prompt;
            this.collection = collection;
            this.provider = provider;
        }
    }

    /** Both guarded by this registry. */
    private final Map<String, Open> byCollection = new HashMap<>();
    private final Map<String, Open> byPrompt = new HashMap<>();
    /** Whether the Completed signals reach this registry; without them each unlock asks anew. */
    private final boolean following;

    /**
     * Holds no reference to {@code connection}: the connection holds the handler, and the handler
     * this registry, so that the map's weak key lets both go with the connection.
     */
    private UnlockPrompts(DBusConnection connection) {
        boolean registered = false;
        try {
            connection.addSigHandler(Prompt.Completed.class, this::completed);
            registered = true;
        } catch (DBusException e) {
            log.warn("Cannot follow the unlock prompts of gnome-keyring; each unlock asks anew.", e);
        }
        following = registered;
    }

    /** The registry of {@code connection}. */
    static UnlockPrompts of(DBusConnection connection) {
        synchronized (BY_CONNECTION) {
            return BY_CONNECTION.computeIfAbsent(connection, UnlockPrompts::new);
        }
    }

    /**
     * Unlocks {@code objects}, which belong to the collection at {@code collection}, through
     * gnome-keyring's dialog: waits on the collection's open unlock prompt, or asks gnome-keyring
     * for one and shows it. The prompt stays open when nobody answers within {@code timeout}.
     *
     * @param service     the service to ask, whose connection is this registry's
     * @param prompt      what shows the prompt, on that connection
     * @param lockedState the collection's {@code Locked} property, or empty when it cannot be read:
     *                    the wait ends once the collection is unlocked
     */
    Unlock unlock(Service service, Prompt prompt, List<DBusPath> objects, String collection, Duration timeout,
                  Supplier<Optional<Boolean>> lockedState) {
        if (!following) {
            // Through the prompt's own wait, which leaves an unlock prompt of gnome-keyring open as well.
            Optional<Pair<List<DBusPath>, DBusPath>> reply = service.unlock(objects);
            if (reply.isEmpty()) return Unlock.NO_ANSWER;
            DBusPath path = reply.get().b;
            if (path == null || path.getPath() == null || "/".equals(path.getPath())) return Unlock.DONE;
            Prompt.Completed completed = prompt.await(path, timeout);
            return completed == null ? Unlock.NO_ANSWER : completed.dismissed ? Unlock.REFUSED : Unlock.DONE;
        }
        String provider = secretsOwner(service.getConnection());
        Open open;
        boolean shown;
        synchronized (this) {
            open = byCollection.get(collection);
            if (open != null && !open.provider.equals(provider)) {
                // gnome-keyring started again since, and the prompt went with it.
                forget(open);
                open = null;
            }
            shown = open != null;
            if (!shown) {
                Optional<Pair<List<DBusPath>, DBusPath>> reply = service.unlock(objects);
                if (reply.isEmpty()) return Unlock.NO_ANSWER;
                DBusPath path = reply.get().b;
                if (path == null || path.getPath() == null || "/".equals(path.getPath())) return Unlock.DONE;
                open = new Open(path.getPath(), collection, provider);
                // Before Prompt: its Completed may come at once.
                byCollection.put(collection, open);
                byPrompt.put(open.prompt, open);
            }
        }
        if (shown) {
            log.debug("Waiting on gnome-keyring's open unlock prompt ({}) of collection {}.", open.prompt, collection);
        } else if (!prompt.prompt(new DBusPath(open.prompt))) {
            // No dialog for anyone to wait on.
            synchronized (this) {
                forget(open);
            }
            return Unlock.NO_ANSWER;
        }
        long deadline = java.lang.System.nanoTime() + timeout.toNanos();
        try {
            while (true) {
                long left = deadline - java.lang.System.nanoTime();
                if (left <= 0) {
                    log.info("Left gnome-keyring's unlock prompt ({}) open: nobody answered it in time, and a "
                            + "dismissal can abort gnome-keyring.", open.prompt);
                    return Unlock.NO_ANSWER;
                }
                try {
                    return open.completed.get(Math.min(left, LOCK_CHECK.toNanos()), TimeUnit.NANOSECONDS).dismissed
                            ? Unlock.REFUSED : Unlock.DONE;
                } catch (TimeoutException e) {
                    // gnome-keyring 51 strands an unlock prompt that waits behind a dialog whose own
                    // prompt another client dismissed: the answer to that dialog unlocks the
                    // collection, and the prompt never completes. It is forgotten then, and the
                    // next request asks anew.
                    if (Boolean.FALSE.equals(lockedState.get().orElse(null))) {
                        synchronized (this) {
                            forget(open);
                        }
                        log.debug("Collection {} was unlocked while its unlock prompt ({}) waited.",
                                collection, open.prompt);
                        return Unlock.DONE;
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Unlock.NO_ANSWER;
        } catch (ExecutionException e) {
            return Unlock.NO_ANSWER;
        }
    }

    /** Ends the open prompt whose {@code Completed} arrived. */
    private void completed(Prompt.Completed signal) {
        Open open;
        synchronized (this) {
            open = byPrompt.get(signal.getPath());
            if (open != null) forget(open);
        }
        if (open != null) open.completed.complete(signal);
    }

    /** The caller holds this registry's lock. */
    private void forget(Open open) {
        byPrompt.remove(open.prompt, open);
        byCollection.remove(open.collection, open);
    }

    /** The unique name of the connection that serves the secrets, or "" when it cannot be read. */
    private static String secretsOwner(DBusConnection connection) {
        try {
            return connection.getRemoteObject("org.freedesktop.DBus", "/org/freedesktop/DBus", DBus.class)
                    .GetNameOwner("org.freedesktop.secrets");
        } catch (DBusException | RuntimeException e) {
            log.debug("Could not read who serves the secrets.", e);
            return "";
        }
    }
}
