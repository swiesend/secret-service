package de.swiesend.secretservice.simple.interfaces;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Base interface for the legacy simple API.
 *
 * @deprecated since 2.0, for removal in 3.0. Use the functional API via
 *             {@link de.swiesend.secretservice.functional.SecretService#create()} instead.
 */
@Deprecated(since = "2.0", forRemoval = true)
public abstract class SimpleCollection implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollection.class);

    /** @deprecated see class-level deprecation notice. */
    @Deprecated(since = "2.0", forRemoval = true)
    public static boolean isAvailable() {
        log.warn("Do not call the interface's method, but the implementation.");
        return false;
    }

    /** @deprecated see class-level deprecation notice. */
    @Deprecated(since = "2.0", forRemoval = true)
    public static boolean isConnected() {
        log.warn("Do not call the interface's method, but the implementation.");
        return false;
    }

    /** @deprecated see class-level deprecation notice. */
    @Deprecated(since = "2.0", forRemoval = true)
    synchronized public static boolean disconnect() {
        log.warn("Do not call the interface's method, but the implementation.");
        return false; }

    public SimpleCollection() throws IOException {};

    public SimpleCollection(String label, CharSequence password) throws IOException {};

    public abstract void clear();

    public abstract void close();

    public abstract String createItem(String label, CharSequence password) throws IllegalArgumentException;

    public abstract String createItem(String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException;

    public abstract void delete() throws SecurityException;

    public abstract void deleteItem(String objectPath) throws SecurityException;

    public abstract void deleteItems(List<String> objectPaths) throws SecurityException;

    public abstract Map<String, String> getAttributes(String objectPath);

    public abstract List<String> getItems(Map<String, String> attributes);

    public abstract String getLabel(String objectPath);

    public abstract char[] getSecret(String objectPath);

    public abstract Map<String, char[]> getSecrets() throws SecurityException;

    public abstract Duration getTimeout();

    public abstract boolean isLocked();

    public abstract void lock();

    public abstract void setTimeout(Duration timeout);

    public abstract void unlockWithUserPermission() throws SecurityException;

    public abstract void updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException;

}
