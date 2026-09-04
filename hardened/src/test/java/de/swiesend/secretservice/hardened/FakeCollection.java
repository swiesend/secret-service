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
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

/**
 * In-memory stub of {@link CollectionInterface} for unit tests. Stores items as
 * {@code (label, rawSecret, attributes)} tuples keyed by synthetic object path.
 * Does not simulate transport encryption; {@code rawSecret} is whatever the
 * caller passed to {@code createItem}.
 *
 * <p>Thread-safe: {@code items} is a {@link ConcurrentHashMap} and object paths are unique
 * {@link UUID}s, so concurrent {@code createItem}/read from a concurrency test is safe. (The
 * compound get-then-put hooks like {@code overwriteRawSecret} are only used single-threaded.)</p>
 */
final class FakeCollection implements CollectionInterface {

    record Item(String label, String rawSecret, Map<String, String> attrs) {}

    private final Map<String, Item> items = new ConcurrentHashMap<>();
    private volatile boolean closed;
    private final AtomicBoolean nextCreateFails = new AtomicBoolean(false);
    private final AtomicBoolean nextGetItemsFails = new AtomicBoolean(false);
    private volatile java.util.function.Predicate<Map<String, String>> createFailsWhen;

    Map<String, Item> rawItems() { return Collections.unmodifiableMap(items); }

    void seedPlain(String path, String label, String secret, Map<String, String> attrs) {
        items.put(path, new Item(label, secret, new LinkedHashMap<>(attrs)));
    }

    /** Test hook for replay tests: insert an item with arbitrary already-encoded raw bytes. */
    void seedRaw(String path, String label, String rawSecret, Map<String, String> attrs) {
        items.put(path, new Item(label, rawSecret, new LinkedHashMap<>(attrs)));
    }

    /**
     * Every object path whose BODY was read via {@code withSecret}, in call order. Lets a test
     * assert the decorator's non-destructive contract directly -- that it never decrypts an item
     * belonging to another application.
     */
    private final List<String> secretReads = Collections.synchronizedList(new ArrayList<>());

    /** Paths whose secret body was read since the last {@link #clearSecretReads()}. */
    List<String> secretReads() { return List.copyOf(secretReads); }

    void clearSecretReads() { secretReads.clear(); }

    /** Test hook: next call to createItem returns Optional.empty() without mutating state. */
    void setNextCreateItemFails(boolean v) { this.nextCreateFails.set(v); }

    /** Test hook: next call to getItems returns Optional.empty() -- i.e. the SEARCH FAILED. */
    void setNextGetItemsFails(boolean v) { this.nextGetItemsFails.set(v); }

    /**
     * Test hook: every FILTERED getItems call (non-empty attribute map) returns a SUCCESSFUL empty
     * result regardless of what actually matches, while the empty-map enumeration stays honest.
     * Models the provider-dependent SearchItems unreliability this project documents (see the
     * KeePassXC note in core's Collection.getItems): a wrong-but-successful answer, which the
     * Optional.empty() failure hook above cannot express.
     */
    void setFilteredGetItemsLies(boolean v) { this.filteredGetItemsLies = v; }
    private volatile boolean filteredGetItemsLies = false;

    /** Test hook: next call to getItemLabel returns Optional.empty() -- i.e. the READ FAILED. */
    void setNextGetItemLabelFails(boolean v) { this.nextGetItemLabelFails.set(v); }
    private final java.util.concurrent.atomic.AtomicBoolean nextGetItemLabelFails =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    /**
     * Paths whose reads fail while the item REMAINS PRESENT -- models a locked/denied item or a
     * daemon that stops answering for it. {@code getAttributes}/{@code withSecret} return empty,
     * but {@code itemExists} still answers "present", so a caller must fail closed.
     */
    private final Set<String> unreadable = java.util.concurrent.ConcurrentHashMap.newKeySet();

    void setUnreadable(String path) { unreadable.add(path); }

    /**
     * As {@link #setUnreadable}, but only the BODY fails: attributes still read. Models an item
     * whose secret needs a prompt the user dismissed, and isolates the body guard from the
     * attribute guard that would otherwise trip first.
     */
    private final Set<String> bodyUnreadable = java.util.concurrent.ConcurrentHashMap.newKeySet();

    void setBodyUnreadable(String path) { bodyUnreadable.add(path); unreadable.add(path); }

    /**
     * Paths that report "cannot tell" from {@code itemExists} -- models no reply / disconnected,
     * where nothing may be inferred about existence.
     */
    private final Set<String> existenceUnknown = java.util.concurrent.ConcurrentHashMap.newKeySet();

    void setExistenceUnknown(String path) { unreadable.add(path); existenceUnknown.add(path); }

    /**
     * A path the enumeration keeps reporting after the item is gone -- the ordinary race between
     * listing a shared collection and reading each item, not an error. Reads of it return empty and
     * {@code itemExists} answers "provably absent".
     */
    private final Set<String> phantoms = java.util.concurrent.ConcurrentHashMap.newKeySet();

    void setPhantomPath(String path) { phantoms.add(path); }

    @Override
    public Optional<Boolean> itemExists(String objectPath) {
        if (existenceUnknown.contains(objectPath)) return Optional.empty();   // UNAVAILABLE
        if (unreadable.contains(objectPath)) return Optional.of(true);        // DENIED -> present
        return Optional.of(items.containsKey(objectPath));                    // OK / ABSENT
    }

    /**
     * Test hook: fail createItem for the writes whose attributes match {@code p}. Needed because a
     * one-shot failure can no longer target the rewrap -- rotateEpoch now writes the keystore
     * first, so the first createItem of a rotation is the keystore persist. Pass a predicate that
     * excludes {@code hardened.kind=epoch-keystore} to fail only item rewraps.
     */
    void setCreateItemFailsWhen(java.util.function.Predicate<Map<String, String>> p) {
        this.createFailsWhen = p;
    }

    /** Test hook: drop one plaintext attribute (models a hostile/buggy daemon, or a lossy search). */
    void removeAttribute(String path, String key) {
        Item it = items.get(path);
        if (it == null) throw new IllegalArgumentException("no such item: " + path);
        Map<String, String> attrs = new java.util.HashMap<>(it.attrs());
        attrs.remove(key);
        items.put(path, new Item(it.label(), it.rawSecret(), attrs));
    }

    /** Test hook: rewrite one plaintext attribute (models a hostile/buggy daemon). */
    void overwriteAttribute(String path, String key, String value) {
        Item it = items.get(path);
        if (it == null) throw new IllegalArgumentException("no such item: " + path);
        Map<String, String> attrs = new java.util.HashMap<>(it.attrs());
        attrs.put(key, value);
        items.put(path, new Item(it.label(), it.rawSecret(), attrs));
    }

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
        if (nextCreateFails.getAndSet(false)) {
            return Optional.empty();
        }
        java.util.function.Predicate<Map<String, String>> p = createFailsWhen;
        if (p != null && p.test(attributes)) {
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
        // bodyUnreadable leaves attributes readable on purpose; only the secret fails.
        if (unreadable.contains(objectPath) && !bodyUnreadable.contains(objectPath)) {
            return Optional.empty(); // present, but we can't read it
        }
        Item it = items.get(objectPath);
        return it == null ? Optional.empty() : Optional.of(new HashMap<>(it.attrs));
    }

    @Override
    public Optional<List<String>> getItems(Map<String, String> attributes) {
        if (nextGetItemsFails.getAndSet(false)) {
            return Optional.empty(); // models a failed search, NOT an empty result
        }
        if (filteredGetItemsLies && !attributes.isEmpty()) {
            return Optional.of(List.of()); // a SUCCESSFUL lie: search "worked", found nothing
        }
        List<String> matched = new ArrayList<>();
        for (Map.Entry<String, Item> e : items.entrySet()) {
            boolean ok = true;
            for (Map.Entry<String, String> req : attributes.entrySet()) {
                if (!req.getValue().equals(e.getValue().attrs.get(req.getKey()))) { ok = false; break; }
            }
            if (ok) matched.add(e.getKey());
        }
        // Stale entries the daemon still lists though the item is gone; only the unfiltered
        // enumeration reports them, which is where the classification race actually happens.
        if (attributes.isEmpty()) matched.addAll(phantoms);
        return Optional.of(matched);
    }

    @Override
    public Optional<String> getItemLabel(String objectPath) {
        if (nextGetItemLabelFails.getAndSet(false)) {
            return Optional.empty(); // models a failed label read
        }
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
        secretReads.add(objectPath);
        if (unreadable.contains(objectPath)) return Optional.empty(); // present, but we can't read it
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
