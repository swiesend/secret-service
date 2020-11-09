package org.freedesktop.secret.simple.interfaces;

import java.io.IOException;
import java.security.AccessControlException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public abstract class SimpleCollection implements AutoCloseable {

    public static boolean isAvailable() {
        return false;
    }

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

    public abstract Duration getTimeout();

    public abstract Map<String, char[]> getSecrets() throws AccessControlException;

    public abstract void lock();

    public abstract void setTimeout(Duration timeout);

    public abstract void unlockWithUserPermission() throws AccessControlException;

    public abstract void updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) throws IllegalArgumentException;

}
