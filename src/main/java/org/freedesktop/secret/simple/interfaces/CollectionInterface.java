package org.freedesktop.secret.simple.interfaces;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface CollectionInterface extends AutoCloseable {

    Optional<Boolean> clear();

    Optional<String> createItem(String label, CharSequence password);

    Optional<String> createItem(String label, CharSequence password, Map<String, String> attributes);

    Optional<Boolean> delete();

    Optional<Boolean> deleteItem(String objectPath);

    Optional<Boolean> deleteItems(List<String> objectPaths);

    Optional<Map<String, String>> getAttributes(String objectPath);

    Optional<List<String>> getItems(Map<String, String> attributes);

    Optional<String> getLabel(String objectPath);

    Optional<String> setLabel(String objectPath);

    Optional<char[]> getSecret(String objectPath);

    Optional<Map<String, char[]>> getSecrets();

    Optional<Boolean> isLocked();

    Optional<Boolean> lock();

    Optional<Boolean> unlockWithUserPermission();

    Optional<Boolean> updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes);

}
