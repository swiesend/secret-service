package de.swiesend.secretservice.simple;

import de.swiesend.secretservice.*;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.exceptions.DBusExecutionException;
import org.freedesktop.dbus.interfaces.DBus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.RejectedExecutionException;

import static de.swiesend.secretservice.Static.DBus.DEFAULT_DELAY_MILLIS;
import static de.swiesend.secretservice.Static.DBus.MAX_DELAY_MILLIS;
import static de.swiesend.secretservice.Static.DEFAULT_PROMPT_TIMEOUT;

/**
 * High-level API for storing secrets in the user's keyring.
 *
 * <p><strong>Deprecated.</strong> This class preserves the original 1.x API surface
 * (static shared D-Bus connection, {@code null} returns, checked exceptions) for backward
 * compatibility only. It will be removed in version 3.0.</p>
 *
 * <p><strong>Migration:</strong> Replace usages with the functional API:
 * <pre>{@code
 * try (var sys    = de.swiesend.secretservice.functional.System.connect();
 *      var svc    = SecretService.create(Optional.of(sys)).orElseThrow();
 *      var sess   = svc.openSession().orElseThrow();
 *      var col    = Collection.openDefault(Optional.of(sess)).orElseThrow()) {
 *     col.createItem("My label", "s3cr3t", Map.of());
 * }
 * }</pre>
 * </p>
 *
 * @deprecated since 2.0, for removal in 3.0. Use
 *             {@link de.swiesend.secretservice.functional.SecretService#create()} and the
 *             {@link de.swiesend.secretservice.functional.interfaces.CollectionInterface} instead.
 */
@Deprecated(since = "2.0", forRemoval = true)
public final class SimpleCollection extends de.swiesend.secretservice.simple.interfaces.SimpleCollection {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollection.class);
    private static final DBusConnection connection = getConnection();
    private static final Thread shutdownHook = setupShutdownHook();

    private ServiceInterface service = null;
    private SessionInterface session = null;
    private CollectionInterface delegate = null;
    private Duration timeout = DEFAULT_PROMPT_TIMEOUT;

    /**
     * Opens the default collection.
     *
     * @throws IOException Could not communicate properly with the DBus. Check the logs.
     * @deprecated since 2.0, for removal in 3.0. Use
     *             {@link de.swiesend.secretservice.functional.Collection#openDefault} instead.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    public SimpleCollection() throws IOException {
        try {
            init();
            delegate = de.swiesend.secretservice.functional.Collection
                    .openDefault(Optional.of(session))
                    .orElseThrow(() -> new IOException("Could not open the default collection."));
        } catch (RuntimeException e) {
            throw new IOException("Could not initialize the secret service.", e);
        }
    }

    /**
     * A user specified collection.
     *
     * @param label    The displayable label of the collection
     *
     *                 <p>
     *                 NOTE: The <code>label</code> of a collection may differ from the <code>id</code> of a collection.
     *                 The <code>id</code> is assigned by the Secret Service and used in the DBus object path of a
     *                 collection or item.
     *                 </p>
     *                 <p>
     *                 The SimpleCollection can't handle collections with the same label, but different ids correctly,
     *                 as the <code>id</code> is inferred by the given label.
     * @param password Password of the collection
     * @throws IOException Could not communicate properly with the DBus. Check the logs.
     * @deprecated since 2.0, for removal in 3.0. Use
     *             {@link de.swiesend.secretservice.functional.Collection#open} instead.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    public SimpleCollection(String label, CharSequence password) throws IOException {
        try {
            init();
            Optional<CharSequence> maybePassword = Optional.ofNullable(password);
            delegate = de.swiesend.secretservice.functional.Collection
                    .open(label, maybePassword, Optional.of(session))
                    .orElseThrow(() -> new IOException(
                            String.format("Could not acquire collection with name %s", label)));
        } catch (RuntimeException e) {
            throw new IOException("Could not initialize the secret service.", e);
        }
    }

    /**
     * Try to get a new DBus connection.
     *
     * @return a new DBusConnection or null
     * @deprecated see class-level deprecation notice.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    private static DBusConnection getConnection() {
        try {
            return DBusConnectionBuilder.forSessionBus().withShared(false).build();
        } catch (DBusException | DBusExecutionException e) {
            if (e == null) {
                log.warn("Could not communicate properly with the D-Bus.");
            } else {
                log.warn("Could not communicate properly with the D-Bus [" + e.getClass().getSimpleName() + "]: " + e.getMessage());
            }
        }
        return null;
    }

    /**
     * Checks the D-Bus connection status.
     *
     * @return true if connected to the D-Bus, otherwise false
     * @deprecated see class-level deprecation notice.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    public static boolean isConnected() {
        if (connection != null) {
            return connection.isConnected();
        } else {
            return false;
        }
    }

    /**
     * Checks if all services are provided by the system:<br>
     * <code>org.freedesktop.DBus</code><br>
     * <code>org.freedesktop.secrets</code><br>
     * <code>org.gnome.keyring</code>
     *
     * @return true if the secret service is available, otherwise false and will log an error message.
     * @deprecated see class-level deprecation notice.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    public static boolean isAvailable() {
        if (connection != null && connection.isConnected()) {
            try {
                DBus bus = connection.getRemoteObject(
                        Static.DBus.Service.DBUS,
                        Static.DBus.ObjectPaths.DBUS,
                        DBus.class);

                // Check both running services and activatable services.
                // A service is available if it appears in either list.
                Set<String> available = new HashSet<>();
                available.addAll(Arrays.asList(bus.ListNames()));
                available.addAll(Arrays.asList(bus.ListActivatableNames()));

                // Required: org.freedesktop.DBus, org.freedesktop.secrets
                if (!available.contains(Static.DBus.Service.DBUS) || !available.contains(Static.Service.SECRETS)) {
                    log.error("Missing required D-Bus service. Available: " + available);
                    return false;
                }

                // Optional: org.gnome.keyring
                if (!available.contains(de.swiesend.secretservice.gnome.keyring.Static.Service.KEYRING)) {
                    log.warn("Proceeding without optional D-Bus service: " +
                            de.swiesend.secretservice.gnome.keyring.Static.Service.KEYRING);
                }

                // The following calls intent to open a session without actually generating a session.
                // Necessary in order to check if the secret service supports the expected transport encryption
                // algorithm (DH_IETF1024_SHA256_AES128_CBC_PKCS7) or raises an error, like
                // "org.freedesktop.DBus.Error.ServiceUnknown <: org.freedesktop.dbus.exceptions.DBusException"
                TransportEncryption transport = new TransportEncryption(connection);
                Optional<TransportEncryption.OpenedSession> opened = transport.initialize().flatMap(init -> init.openSession());
                boolean isSessionSupported = opened.isPresent();
                transport.close();

                return isSessionSupported;
            } catch (DBusException | ExceptionInInitializerError e) {
                log.warn("The secret service is not available. You may want to install the `gnome-keyring` package. Is the `gnome-keyring-daemon` running?", e);
                return false;
            }
        } else {
            log.error("No D-Bus connection: Cannot check if all needed services are available.");
            return false;
        }
    }

    /**
     * Checks if private/unsupported services are provided by the system:<br>
     * <code>org.gnome.keyring</code>
     *
     * @return true if the secret service provider is gnome keyring, otherwise false and will log a warning message.
     * @deprecated see class-level deprecation notice.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    public static boolean isGnomeKeyringAvailable() {
        if (connection != null && connection.isConnected()) {
            try {
                DBus bus = connection.getRemoteObject(
                        Static.DBus.Service.DBUS,
                        Static.DBus.ObjectPaths.DBUS,
                        DBus.class);

                // Check both running and activatable services
                Set<String> available = new HashSet<>();
                available.addAll(Arrays.asList(bus.ListNames()));
                available.addAll(Arrays.asList(bus.ListActivatableNames()));
                if (!available.contains(
                        de.swiesend.secretservice.gnome.keyring.Static.Service.KEYRING)) {
                    return false;
                }
            } catch (DBusException | ExceptionInInitializerError e) {
                log.warn("The secret service is not available. You may want to install the `gnome-keyring` package. Is the `gnome-keyring-daemon` running?", e);
                return false;
            }
        } else {
            log.warn("Secret service provider is not Gnome Keyring: Some operations are not supported.");
            return false;
        }

        return true;
    }

    /**
     * Close the DBus connection immediately. Waits for the DBus connection to close within 2 seconds.
     *
     * @deprecated see class-level deprecation notice.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    synchronized public static boolean disconnect() {
        try {
            if (connection != null && connection.isConnected()) {
                connection.close();
                long count = 0L;
                while (count < MAX_DELAY_MILLIS && connection.isConnected()) {
                    Thread.sleep(DEFAULT_DELAY_MILLIS);
                    count += DEFAULT_DELAY_MILLIS;
                }
                if (connection.isConnected()) {
                    log.warn("Failed to disconnect properly from the D-Bus. There are probably one or more connections left open.");
                    return false;
                } else {
                    log.debug("Disconnected properly from the D-Bus.");
                    return true;
                }
            }
        } catch (IOException | RejectedExecutionException | InterruptedException e) {
            log.error("Failed to disconnect properly from the D-Bus.", e);
            return false;
        }
        return false;
    }

    /**
     * Sets up a shutdown hook to close the global D-Bus connection eventually at the end of the static lifetime.
     */
    private static Thread setupShutdownHook() {
        Thread daemonThread = new Thread(() -> disconnect());
        daemonThread.setName("secret-service:disconnect-shutdown");
        daemonThread.setDaemon(true);
        Runtime.getRuntime().addShutdownHook(daemonThread);
        return daemonThread;
    }

    private void init() throws IOException {
        if (!isAvailable()) throw new IOException("The secret service is not available.");
        // Wrap the static connection so the functional layer shares it rather than
        // opening its own. The wrapped SystemInterface does not own the connection,
        // so the static disconnect()/shutdown-hook lifecycle remains in control.
        SystemInterface system = de.swiesend.secretservice.functional.System.wrap(connection);
        ServiceInterface createdService = SecretService.create(Optional.of(system))
                .orElseThrow(() -> new IOException("Could not create the secret service."));
        SessionInterface openedSession;
        try {
            openedSession = createdService.openSession()
                    .orElseThrow(() -> new IOException("Could not open an encrypted session."));
        } catch (RuntimeException | IOException e) {
            try {
                createdService.close();
            } catch (Exception closeException) {
                log.warn("Failed to close secret service after session initialization failure.", closeException);
            }
            throw e;
        }
        service = createdService;
        session = openedSession;
        service.setTimeout(timeout);
    }

    @Override
    public void lock() {
        delegate.lock();
    }

    /**
     * Locks and unlocks the default collection explicitly.
     * <p>
     * The default collection gets only locked on the first call of a session.
     * <p>
     * Once the default collection is unlocked the user will not be prompted again
     * as long as the default collection stays unlocked.
     * <p>
     * This method is used to enforce user interaction for:
     * <p>
     * {@link SimpleCollection#getSecrets()}
     * <p>
     * {@link SimpleCollection#deleteItem(String)}
     * <p>
     * {@link SimpleCollection#deleteItems(List)}
     *
     * @throws SecurityException if the user does not provide the correct credentials.
     */
    @Override
    public void unlockWithUserPermission() throws SecurityException {
        if (!delegate.unlockWithUserPermission()) {
            throw new SecurityException("The collection was not unlocked with user permission.");
        }
    }

    /**
     * Clears the private key of the transport encryption and the passphrase of the collection.
     */
    @Override
    public void clear() {
        delegate.clear();
    }

    @Override
    public void close() {
        try {
            delegate.close();
            log.debug("Closed delegate collection properly.");
        } catch (Exception e) {
            log.error("Failed to close delegate collection.", e);
        } finally {
            try {
                service.close();
                log.debug("Closed secret service properly.");
            } catch (Exception e) {
                log.error("Failed to close secret service.", e);
            }
        }
    }

    /**
     * Delete this collection.
     */
    @Override
    public void delete() throws SecurityException {
        if (!delegate.delete()) {
            throw new SecurityException("Default collections may not be deleted with the simple API.");
        }
    }

    /**
     * Creates an item with the provided properties in this collection.
     *
     * @param label      The displayable label of the new item
     * @param password   The password of the new item
     * @param attributes The attributes of the new item
     * @return DBus object path or null
     * @throws IllegalArgumentException The label and password are non-nullable.
     */
    @Override
    public String createItem(String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException {
        if (Static.Utils.isNullOrEmpty(password)) {
            throw new IllegalArgumentException("The password may not be null or empty.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The label of the item may not be null.");
        }
        return delegate.createItem(label, password, attributes).orElse(null);
    }

    /**
     * Creates an item with the provided properties in this collection.
     *
     * @param label    The displayable label of the new item
     * @param password The password of the new item
     * @return DBus object path
     * @throws IllegalArgumentException The label and password are non-nullable.
     */
    @Override
    public String createItem(String label, CharSequence password) throws IllegalArgumentException {
        return createItem(label, password, null);
    }

    /**
     * Updates an item with the provided properties.
     *
     * @param objectPath The DBus object path of the item
     * @param label      The displayable label of the new item
     * @param password   The password of the new item
     * @param attributes The attributes of the new item
     * @throws IllegalArgumentException The object path, label and password are non-nullable.
     */
    @Override
    public void updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException {
        if (Static.Utils.isNullOrEmpty(objectPath)) {
            throw new IllegalArgumentException("The object path of the item may not be null or empty.");
        }
        delegate.updateItem(objectPath, label, password, attributes);
    }

    /**
     * Get the displayable label of an item.
     *
     * @param objectPath The DBus object path of the item
     * @return label or null
     */
    @Override
    public String getLabel(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return null;
        return delegate.getItemLabel(objectPath).orElse(null);
    }

    /**
     * Get the user specified attributes of an item.
     * <p>
     * The attributes can contain an additional <code>xdg:schema</code> key-value pair.
     *
     * @param objectPath The DBus object path of the item
     * @return item attributes or null
     */
    @Override
    public Map<String, String> getAttributes(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return null;
        return delegate.getAttributes(objectPath).orElse(null);
    }

    /**
     * Get the object paths of items with given attributes.
     *
     * @param attributes The attributes of the secret
     * @return object paths or null
     */
    @Override
    public List<String> getItems(Map<String, String> attributes) {
        if (attributes == null) return null;
        return delegate.getItems(attributes).orElse(null);
    }

    /**
     * Get the secret of the item.
     *
     * @param objectPath The DBus object path of the item
     * @return plain chars or null
     */
    @Override
    public char[] getSecret(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return null;
        return delegate.getSecret(objectPath).orElse(null);
    }

    /**
     * Get the secrets from this collection.
     * <p>
     * Retrieving all passwords form the default collection requires user permission.
     * <p>
     * see: {@link SimpleCollection#unlockWithUserPermission()}
     *
     * @return Mapping of DBus object paths and plain chars or null
     */
    @Override
    public Map<String, char[]> getSecrets() throws SecurityException {
        unlockWithUserPermission();

        return delegate.getSecrets().orElse(null);
    }

    /**
     * Delete an item from this collection.
     * <p>
     * Deleting a password form the default collection requires user permission.
     * <p>
     * see: {@link SimpleCollection#unlockWithUserPermission()}
     *
     * @param objectPath The DBus object path of the item
     */
    @Override
    public void deleteItem(String objectPath) throws SecurityException {
        if (Static.Utils.isNullOrEmpty(objectPath)) throw new SecurityException("Cannot delete an unspecified item.");
        if (!delegate.deleteItem(objectPath)) {
            throw new SecurityException("Failed to delete item. User permission may be denied or the collection may be locked.");
        }
    }

    /**
     * Delete specified items from this collection.
     * <p>
     * Deleting passwords form the default collection requires user permission.
     * <p>
     * see: {@link SimpleCollection#unlockWithUserPermission()}
     *
     * @param objectPaths The DBus object paths of the items
     */
    @Override
    public void deleteItems(List<String> objectPaths) throws SecurityException {
        if (objectPaths == null || objectPaths.isEmpty()) {
            throw new SecurityException("Cannot delete unspecified items.");
        }

        unlockWithUserPermission();

        if (!delegate.deleteItems(objectPaths)) {
            throw new SecurityException("Failed to delete one or more specified items.");
        }
    }

    @Override
    public Duration getTimeout() {
        return timeout;
    }

    @Override
    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
        if (service != null) {
            service.setTimeout(timeout);
        }
    }

    @Override
    public boolean isLocked() {
        return delegate.isLocked();
    }

}
