package org.freedesktop.secret.simple.interfaces;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface CollectionInterface extends AutoCloseable {

    boolean clear();

    Optional<String> createItem(String label, CharSequence password);

    Optional<String> createItem(String label, CharSequence password, Map<String, String> attributes);

    boolean delete();

    boolean deleteItem(String objectPath);

    boolean deleteItems(List<String> objectPaths);

    Optional<Map<String, String>> getAttributes(String objectPath);

    Optional<List<String>> getItems(Map<String, String> attributes);

    Optional<String> getLabel(String objectPath);

    Optional<String> setLabel(String objectPath);

    Optional<char[]> getSecret(String objectPath);

    Optional<Map<String, char[]>> getSecrets();

    boolean isLocked();

    boolean lock();

    boolean unlockWithUserPermission();

    boolean updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes);

}
