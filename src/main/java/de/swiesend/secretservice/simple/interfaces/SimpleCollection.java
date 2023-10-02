package de.swiesend.secretservice.simple.interfaces;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.AccessControlException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public abstract class SimpleCollection implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SimpleCollection.class);

    public static boolean isAvailable() {
        log.warn("Do not call the interface's method, but the implementation.");
        return false;
    }

    public static boolean isConnected() {
        log.warn("Do not call the interface's method, but the implementation.");
        return false;
    }

    synchronized public static boolean disconnect() {
        log.warn("Do not call the interface's method, but the implementation.");
        return false; }

    public SimpleCollection() throws IOException {};

    public SimpleCollection(String label, CharSequence password) throws IOException {};

    public abstract void clear();

    public abstract void close();

    public abstract String createItem(String label, CharSequence password) throws IllegalArgumentException;

    public abstract String createItem(String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException;

    public abstract void delete() throws AccessControlException;

    public abstract void deleteItem(String objectPath) throws AccessControlException;

    public abstract void deleteItems(List<String> objectPaths) throws AccessControlException;

    public abstract Map<String, String> getAttributes(String objectPath);

    public abstract List<String> getItems(Map<String, String> attributes);

    public abstract String getLabel(String objectPath);

    public abstract char[] getSecret(String objectPath);

    public abstract Map<String, char[]> getSecrets() throws AccessControlException;

    public abstract Duration getTimeout();

    public abstract boolean isLocked();

    public abstract void lock();

    public abstract void setTimeout(Duration timeout);

    public abstract void unlockWithUserPermission() throws AccessControlException;

    public abstract void updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException;

}
