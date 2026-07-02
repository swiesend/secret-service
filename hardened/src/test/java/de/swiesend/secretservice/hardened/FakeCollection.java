package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.ProviderDetector;
import de.swiesend.secretservice.functional.SearchMode;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

/**
 * In-memory stub of {@link CollectionInterface} for unit tests. Stores items as
 * {@code (label, rawSecret, attributes)} tuples keyed by synthetic object path.
 * Does not simulate transport encryption; {@code rawSecret} is whatever the
 * caller passed to {@code createItem}.
 */
final class FakeCollection implements CollectionInterface {

    record Item(String label, String rawSecret, Map<String, String> attrs) {}

    private final Map<String, Item> items = new LinkedHashMap<>();
    private boolean closed;
    private boolean nextCreateFails = false;

    Map<String, Item> rawItems() { return Collections.unmodifiableMap(items); }

    void seedPlain(String path, String label, String secret, Map<String, String> attrs) {
        items.put(path, new Item(label, secret, new LinkedHashMap<>(attrs)));
    }

    /** Test hook for replay tests: insert an item with arbitrary already-encoded raw bytes. */
    void seedRaw(String path, String label, String rawSecret, Map<String, String> attrs) {
        items.put(path, new Item(label, rawSecret, new LinkedHashMap<>(attrs)));
    }

    /** Test hook: next call to createItem returns Optional.empty() without mutating state. */
    void setNextCreateItemFails(boolean v) { this.nextCreateFails = v; }

    /** Test hook: replace the stored secret body for an item (simulates tampering). */
    void overwriteRawSecret(String path, String newRawSecret) {
        Item it = items.get(path);
        if (it == null) throw new IllegalStateException("no such item: " + path);
        items.put(path, new Item(it.label, newRawSecret, it.attrs));
    }

    @Override public boolean clear() { items.clear(); return true; }

    @Override
    public Optional<String> createItem(String label, CharSequence secret) {
        return createItem(label, secret, Map.of());
    }

    @Override
    public Optional<String> createItem(String label, CharSequence secret, Map<String, String> attributes) {
        if (nextCreateFails) {
            nextCreateFails = false;
            return Optional.empty();
        }
        String path = "/org/freedesktop/secrets/collection/test/" + UUID.randomUUID();
        items.put(path, new Item(label, secret.toString(), new LinkedHashMap<>(attributes)));
        return Optional.of(path);
    }

    @Override public boolean delete() { items.clear(); return true; }

    @Override public boolean deleteItem(String objectPath) { return items.remove(objectPath) != null; }

    @Override
    public boolean deleteItems(List<String> objectPaths) {
        boolean all = true;
        for (String p : objectPaths) all &= deleteItem(p);
        return all;
    }

    @Override
    public Optional<Map<String, String>> getAttributes(String objectPath) {
        Item it = items.get(objectPath);
        return it == null ? Optional.empty() : Optional.of(new HashMap<>(it.attrs));
    }

    @Override
    public Optional<List<String>> getItems(Map<String, String> attributes) {
        List<String> matched = new ArrayList<>();
        for (Map.Entry<String, Item> e : items.entrySet()) {
            boolean ok = true;
            for (Map.Entry<String, String> req : attributes.entrySet()) {
                if (!req.getValue().equals(e.getValue().attrs.get(req.getKey()))) { ok = false; break; }
            }
            if (ok) matched.add(e.getKey());
        }
        return Optional.of(matched);
    }

    @Override
    public Optional<String> getItemLabel(String objectPath) {
        Item it = items.get(objectPath);
        return it == null ? Optional.empty() : Optional.of(it.label);
    }

    @Override
    public boolean setItemLabel(String objectPath, String label) {
        Item it = items.get(objectPath);
        if (it == null) return false;
        items.put(objectPath, new Item(label, it.rawSecret, it.attrs));
        return true;
    }

    @Override public boolean setLabel(String label) { return true; }
    @Override public Optional<String> getLabel() { return Optional.of("test-collection"); }
    @Override public Optional<String> getId() { return Optional.of("test"); }

    @Override
    public Optional<char[]> getSecret(String objectPath) {
        Item it = items.get(objectPath);
        return it == null ? Optional.empty() : Optional.of(it.rawSecret.toCharArray());
    }

    @Override
    public <R> Optional<R> withSecret(String objectPath, Function<char[], R> callback) {
        Item it = items.get(objectPath);
        if (it == null) return Optional.empty();
        char[] chars = it.rawSecret.toCharArray();
        try {
            R r = callback.apply(chars);
            return Optional.ofNullable(r);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    @Override
    public Optional<Map<String, char[]>> getSecrets() {
        Map<String, char[]> out = new LinkedHashMap<>();
        for (Map.Entry<String, Item> e : items.entrySet()) {
            out.put(e.getKey(), e.getValue().rawSecret.toCharArray());
        }
        return Optional.of(out);
    }

    @Override
    public <R> Optional<R> withSecrets(Function<Map<String, char[]>, R> callback) {
        Map<String, char[]> snap = new LinkedHashMap<>();
        for (Map.Entry<String, Item> e : items.entrySet()) {
            snap.put(e.getKey(), e.getValue().rawSecret.toCharArray());
        }
        try {
            R r = callback.apply(snap);
            return Optional.ofNullable(r);
        } finally {
            for (char[] v : snap.values()) Arrays.fill(v, '\0');
        }
    }

    @Override
    public List<String> search(String query, SearchMode mode) {
        return search(query, mode, 0);
    }

    @Override
    public List<String> search(String query, SearchMode mode, int maxDistance) {
        List<String> matched = new ArrayList<>();
        String q = query.toLowerCase();
        for (Map.Entry<String, Item> e : items.entrySet()) {
            String candidate = switch (mode) {
                case BY_NAME -> e.getValue().label;
                case BY_OBJECT_ID, BY_OBJECT_PATH -> e.getKey();
                case BY_ATTRIBUTE_KEY -> String.join(" ", e.getValue().attrs.keySet());
                case BY_ATTRIBUTE_VALUE -> String.join(" ", e.getValue().attrs.values());
            };
            if (candidate.toLowerCase().contains(q)) matched.add(e.getKey());
        }
        return Collections.unmodifiableList(matched);
    }

    @Override public String getProvider() { return "fake"; }
    @Override public ProviderDetector.Provider detectProvider() { return ProviderDetector.Provider.UNKNOWN; }

    @Override public boolean isLocked() { return false; }
    @Override public boolean lock() { return true; }
    @Override public boolean unlockWithUserPermission() { return true; }

    @Override
    public boolean updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) {
        Item it = items.get(objectPath);
        if (it == null) return false;
        items.put(objectPath, new Item(label, password.toString(), new LinkedHashMap<>(attributes)));
        return true;
    }

    @Override public boolean lockItem(String objectPath) { return true; }
    @Override public boolean unlockItem(String objectPath) { return true; }
    @Override public boolean disablePrompt() { return true; }
    @Override public boolean enablePrompt() { return true; }

    @Override public void close() { closed = true; }
    boolean isClosed() { return closed; }
}
