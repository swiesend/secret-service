package de.swiesend.secretservice;

import org.freedesktop.Secret.Error.IsLocked;
import org.freedesktop.Secret.Error.NoSession;
import org.freedesktop.Secret.Error.NoSuchObject;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.errors.NotSupported;
import org.freedesktop.dbus.errors.PropertyReadOnly;
import org.freedesktop.dbus.errors.UnknownProperty;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.interfaces.Properties;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * An in-process {@code org.freedesktop.secrets} provider for tests. It implements every method of
 * the Secret Service API -- Service, Collection, Item, Session and Prompt, with their properties
 * and signals -- and gnome-keyring's {@code InternalUnsupportedGuiltRiddenInterface}, on an
 * in-memory store.
 *
 * <p>It exists for the conditions that no provider in CI reproduces. The first was issue #45: an
 * item locked <b>individually</b>. gnome-keyring never locks single items, and the KeePassXC
 * container sets {@code ConfirmAccessItem=false}, switching the behaviour off. The asymmetry is the
 * whole point: {@code Unlock} on the <em>collection</em> path leaves the item locked; only
 * {@code Unlock} on the <em>item</em> path clears it, through a prompt, as on KeePassXC. A client
 * that unlocks just the collection therefore cannot read the secret.</p>
 *
 * <p>Prompts are real objects. The fake answers a prompt only when the client calls
 * {@code Prompt()} on it, so a client that declines to prompt never sees the change happen. Every
 * call is recorded, so a test can assert what the client sent, and also what it did not send.</p>
 *
 * <p>The store starts with one collection, {@link #COLLECTION_LABEL}, under the alias
 * {@code default}, holding one item, {@link #ITEM_PATH}. This is a test fixture, not a provider: it
 * does no access control and keeps its secrets in plain byte arrays.</p>
 */
public final class FakeSecretService implements AutoCloseable {

    public static final String BUS_NAME = "org.freedesktop.secrets";
    public static final String SERVICE_PATH = "/org/freedesktop/secrets";
    public static final String DEFAULT_ALIAS_PATH = "/org/freedesktop/secrets/aliases/default";
    public static final String COLLECTION_PATH = "/org/freedesktop/secrets/collection/fake";
    /** The client resolves a collection by label, so the Label property must match this. */
    public static final String COLLECTION_LABEL = "fake";
    public static final String ITEM_PATH = COLLECTION_PATH + "/1";

    /** What the fake item holds. */
    public static final String SECRET_VALUE = "the-locked-secret";

    private static final String COLLECTION_PREFIX = Static.ObjectPaths.COLLECTION + "/";
    private static final String ALIAS_PREFIX = Static.ObjectPaths.ALIASES + "/";
    private static final String SESSION_PREFIX = Static.ObjectPaths.SESSION + "/";
    private static final String PROMPT_PREFIX = Static.ObjectPaths.PROMPT + "/";
    private static final String ITEM_TYPE = "org.freedesktop.Secret.Item.Type";
    private static final DBusPath NO_PROMPT = new DBusPath("/");

    // ---- wire interfaces -------------------------------------------------------------------
    // The library's own de.swiesend.secretservice.interfaces.* declare Optional<...> returns, which
    // are not valid D-Bus types; they exist to be used as client proxies, with the marshalling done
    // by MessageHandler. To EXPORT an object we need signatures dbus-java can serialise, so they are
    // redeclared here. Pair already extends org.freedesktop.dbus.Tuple with @Position, so it maps to
    // multiple out-arguments as-is.
    //
    // They carry no @DBusInterfaceName, on purpose. dbus-java dispatches an incoming call by member
    // name and signature alone, so the D-Bus names are not needed to be called. And they must not be
    // declared: dbus-java keeps one JVM-wide map from an annotated D-Bus interface name to the Java
    // interface last exported under it, and builds each incoming signal of that interface as that
    // Java interface's nested class. With org.freedesktop.Secret.Prompt mapped to a wire interface
    // here, the client could no longer build Prompt.Completed -- in this test, and in every later
    // test in the same JVM. Introspection shows these Java names instead, and the client never
    // introspects.

    public interface WireService extends DBusInterface {
        Pair<Variant<?>, DBusPath> OpenSession(String algorithm, Variant<?> input);
        Pair<DBusPath, DBusPath> CreateCollection(Map<String, Variant<?>> properties, String alias);
        Pair<List<DBusPath>, List<DBusPath>> SearchItems(Map<String, String> attributes);
        Pair<List<DBusPath>, DBusPath> Unlock(List<DBusPath> objects);
        Pair<List<DBusPath>, DBusPath> Lock(List<DBusPath> objects);
        void LockService();
        DBusPath ChangeLock(DBusPath collection);
        Map<DBusPath, Secret> GetSecrets(List<DBusPath> items, DBusPath session);
        DBusPath ReadAlias(String name);
        void SetAlias(String name, DBusPath collection);
    }

    /** gnome-keyring's extension of the service object. It is not part of the specification. */
    public interface WireGnomeKeyring extends DBusInterface {
        void ChangeWithMasterPassword(DBusPath collection, Secret original, Secret master);
        DBusPath ChangeWithPrompt(DBusPath collection);
        DBusPath CreateWithMasterPassword(Map<String, Variant<?>> properties, Secret master);
        void UnlockWithMasterPassword(DBusPath collection, Secret master);
    }

    public interface WireCollection extends DBusInterface {
        DBusPath Delete();
        List<DBusPath> SearchItems(Map<String, String> attributes);
        Pair<DBusPath, DBusPath> CreateItem(Map<String, Variant<?>> properties, Secret secret, boolean replace);
    }

    public interface WireItem extends DBusInterface {
        DBusPath Delete();
        Secret GetSecret(DBusPath session);
        void SetSecret(Secret secret);
    }

    public interface WireSession extends DBusInterface {
        void Close();
    }

    public interface WirePrompt extends DBusInterface {
        void Prompt(String windowId);
        void Dismiss();
    }

    // ---- state -----------------------------------------------------------------------------
    // One lock guards all of it: dbus-java dispatches calls on a pool of threads, and a test reads
    // the state from its own.

    private static final class CollectionState {
        final String path;
        String label;
        boolean locked;
        /** gnome-keyring's master password; null when none was set, which reads as empty. */
        byte[] password;
        final long created = now();
        long modified = created;
        final Map<String, ItemState> items = new LinkedHashMap<>();
        int nextItem = 1;

        CollectionState(String path, String label) {
            this.path = path;
            this.label = label;
        }
    }

    private static final class ItemState {
        final String path;
        final CollectionState collection;
        String label;
        Map<String, String> attributes;
        byte[] secret;
        String contentType;
        String type = "org.freedesktop.Secret.Generic";
        /** Locked on its own, as KeePassXC locks an item. The collection's lock applies on top. */
        boolean locked;
        final long created = now();
        long modified = created;

        ItemState(String path, CollectionState collection, String label, Map<String, String> attributes,
                  byte[] secret, String contentType) {
            this.path = path;
            this.collection = collection;
            this.label = label;
            this.attributes = new HashMap<>(attributes);
            this.secret = secret;
            this.contentType = contentType;
        }

        /** What a provider reports: gnome-keyring reports an item locked while its collection is. */
        boolean effectivelyLocked() {
            return locked || collection.locked;
        }
    }

    /** {@code key} is the AES session key, or null for a plain session. */
    private record SessionState(byte[] key) {
    }

    private static final class PromptState {
        final String path;
        /** Applies the change the prompt asks for, and returns the result Completed carries. */
        final Supplier<Variant<?>> onApprove;
        boolean shown;

        PromptState(String path, Supplier<Variant<?>> onApprove) {
            this.path = path;
            this.onApprove = onApprove;
        }
    }

    private final Object lock = new Object();
    private final DBusConnection connection;
    private final Map<String, CollectionState> collections = new LinkedHashMap<>();
    /** Alias name to canonical collection path. */
    private final Map<String, String> aliases = new LinkedHashMap<>();
    private final Map<String, SessionState> sessions = new HashMap<>();
    private final Map<String, PromptState> prompts = new HashMap<>();
    private int nextSession = 1;
    private int nextPrompt = 1;

    /** Every call, in order -- see {@link #calls()}. */
    private final List<String> calls = Collections.synchronizedList(new ArrayList<>());
    /** Every path passed to Unlock, in call order -- what the tests assert on. */
    private final List<String> unlockCalls = Collections.synchronizedList(new ArrayList<>());
    /** Every prompt the client showed with Prompt(), in order. */
    private final List<String> promptCalls = Collections.synchronizedList(new ArrayList<>());

    private volatile boolean dismissPrompts;
    private volatile boolean refuseCollectionUnlock;
    private volatile boolean requirePromptForCollectionUnlock;
    private volatile boolean requirePromptForItemLock;
    private volatile boolean requirePromptForDelete;
    private volatile boolean stallItemProperties;

    // Signals go out on a thread of their own, in the order they were raised, so a slow send never
    // holds up the call that raised them.
    private final ExecutorService signals = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "fake-signals");
        thread.setDaemon(true);
        return thread;
    });

    /** @param itemLocked whether {@link #ITEM_PATH} starts out individually locked */
    public FakeSecretService(DBusConnection connection, boolean itemLocked) {
        this.connection = connection;
        CollectionState fake = new CollectionState(COLLECTION_PATH, COLLECTION_LABEL);
        ItemState item = new ItemState(ITEM_PATH, fake, "fake-item", Map.of(),
                SECRET_VALUE.getBytes(StandardCharsets.UTF_8), "text/plain; charset=utf8");
        item.locked = itemLocked;
        fake.items.put(ITEM_PATH, item);
        fake.nextItem = 2;
        collections.put(COLLECTION_PATH, fake);
        aliases.put("default", COLLECTION_PATH);
    }

    public void export() throws DBusException {
        synchronized (lock) {
            connection.exportObject(SERVICE_PATH, new ServiceImpl());
            for (CollectionState c : collections.values()) {
                export(c.path, new CollectionImpl(c, c.path));
                for (ItemState i : c.items.values()) export(i.path, new ItemImpl(i));
            }
            for (Map.Entry<String, String> alias : aliases.entrySet()) {
                exportAlias(alias.getKey(), collections.get(alias.getValue()));
            }
        }
        connection.requestBusName(BUS_NAME);
    }

    /** Waits until every signal raised so far has gone out, then stops the signal thread. */
    @Override
    public void close() {
        awaitSignals();
        signals.shutdownNow();
    }

    /** Waits until every signal raised so far has gone out, so a test does not race them. */
    public void awaitSignals() {
        try {
            signals.submit(() -> { }).get(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (RejectedExecutionException e) {
            // Closed already: nothing is left to send.
        } catch (Exception e) {
            log("fake: signals did not drain: " + e.getClass().getName());
        }
    }

    // ---- what a test observes --------------------------------------------------------------

    /**
     * Every call the fake received, in order, as {@code "Interface.Member path"}: the path the call
     * was addressed to or, for Lock and Unlock, one entry for each object they name. Property calls
     * also name the property.
     */
    public List<String> calls() {
        return List.copyOf(calls);
    }

    /** Paths that {@code Unlock} was called with, in order. */
    public List<String> unlockCalls() {
        return List.copyOf(unlockCalls);
    }

    /** The prompts that the client showed with {@code Prompt()}: the dialogs a user would have seen. */
    public List<String> promptCalls() {
        return List.copyOf(promptCalls);
    }

    /** Whether {@link #ITEM_PATH} is locked on its own. Its collection's lock does not count. */
    public boolean isItemLocked() {
        synchronized (lock) {
            ItemState item = itemAt(ITEM_PATH);
            return item != null && item.locked;
        }
    }

    /** Whether the store holds an item at {@code path}. */
    public boolean hasItem(String path) {
        synchronized (lock) {
            return itemAt(path) != null;
        }
    }

    /** The secret the store holds for the item at {@code path}. */
    public Optional<String> secretOf(String path) {
        synchronized (lock) {
            ItemState item = itemAt(path);
            return item == null ? Optional.empty()
                    : Optional.of(new String(item.secret, StandardCharsets.UTF_8));
        }
    }

    // ---- what a test sets up ---------------------------------------------------------------

    /** Adds an unlocked collection without a prompt, as if another application had created it. */
    public String addCollection(String label) {
        synchronized (lock) {
            return newCollection(label).path;
        }
    }

    /** Adds an item, as if another application had stored it. Returns its path. */
    public String addItem(String collectionPath, String label, String secret, Map<String, String> attributes) {
        synchronized (lock) {
            CollectionState c = collections.get(collectionPath);
            if (c == null) throw new IllegalArgumentException("fake: no collection at " + collectionPath);
            return newItem(c, label, attributes, secret.getBytes(StandardCharsets.UTF_8),
                    "text/plain; charset=utf8").path;
        }
    }

    /** Makes the prompt come back dismissed, as if the user had refused it. */
    public void setDismissPrompts(boolean dismiss) {
        this.dismissPrompts = dismiss;
    }

    /** Locks the collection, as a provider does when the keyring times out or the user locks it. */
    public void lockCollection() {
        synchronized (lock) {
            collections.get(COLLECTION_PATH).locked = true;
        }
    }

    /**
     * Refuses to unlock a collection, as happens when the user dismisses the keyring prompt, the
     * stored password is wrong, or prompting is disabled. This is the state in which a per-item
     * unlock attempt would raise a SECOND prompt.
     */
    public void setRefuseCollectionUnlock(boolean refuse) {
        this.refuseCollectionUnlock = refuse;
    }

    /** Makes a collection unlock ask the user first, as gnome-keyring does. Off: it unlocks at once. */
    public void setRequirePromptForCollectionUnlock(boolean require) {
        this.requirePromptForCollectionUnlock = require;
    }

    /**
     * Makes item Lock require a prompt as well; unlocking a locked item always does. Without it a
     * test cannot tell "the client refused to prompt" from "the operation failed anyway" -- both
     * give the same answer. With it, the operation succeeds when prompting is allowed and fails
     * when it is not, which is the difference under test.
     */
    public void setRequirePromptForItemLock(boolean require) {
        this.requirePromptForItemLock = require;
    }

    /**
     * Makes Item.Delete and Collection.Delete ask the user first, as KeePassXC does with
     * {@code ConfirmDeleteItem}. Off, the default: they delete at once and answer {@code "/"}, as
     * gnome-keyring does.
     */
    public void setRequirePromptForDelete(boolean require) {
        this.requirePromptForDelete = require;
    }

    /**
     * Makes the item's property reads hang past {@code Static.DBus.MAX_DELAY_MILLIS}, so the
     * client's getReply times out. A provider that is merely slow is the commonest failure there
     * is, and the one the OK/ABSENT/UNAVAILABLE distinction most needs to get right.
     */
    public void setStallItemProperties(boolean stall) {
        this.stallItemProperties = stall;
    }

    // ---- implementations -------------------------------------------------------------------

    private final class ServiceImpl implements WireService, WireGnomeKeyring, Properties {

        @Override
        public Pair<Variant<?>, DBusPath> OpenSession(String algorithm, Variant<?> input) {
            record("Service.OpenSession", SERVICE_PATH);
            byte[] key;
            Variant<?> output;
            if (Static.Algorithm.PLAIN.equals(algorithm)) {
                key = null;
                output = new Variant<>("");
            } else if (Static.Algorithm.DH_IETF1024_SHA256_AES128_CBC_PKCS7.equals(algorithm)) {
                // Mirror of TransportEncryption's client half: RFC 2409 Second Oakley Group,
                // HKDF-SHA256 with a null salt and empty info, AES-128.
                try {
                    byte[] clientY = Static.Utils.toByteArray(input.getValue());
                    BigInteger prime = new BigInteger(1, Static.RFC_2409.SecondOakleyGroup.PRIME);
                    DHParameterSpec params = new DHParameterSpec(prime, BigInteger.valueOf(2), 1024);

                    KeyPairGenerator gen = KeyPairGenerator.getInstance("DiffieHellman");
                    gen.initialize(params);
                    KeyPair ours = gen.generateKeyPair();

                    DHPublicKey theirs = (DHPublicKey) KeyFactory.getInstance("DiffieHellman")
                            .generatePublic(new DHPublicKeySpec(
                                    new BigInteger(1, clientY), params.getP(), params.getG()));

                    KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
                    ka.init(ours.getPrivate());
                    ka.doPhase(theirs, true);
                    key = hkdfSha256To128(ka.generateSecret());
                    output = new Variant<>(unsigned(((DHPublicKey) ours.getPublic()).getY()));
                } catch (Exception e) {
                    throw new IllegalStateException("fake OpenSession failed", e);
                }
            } else {
                throw new NotSupported("fake: unsupported algorithm " + algorithm);
            }
            synchronized (lock) {
                String path = SESSION_PREFIX + "s" + nextSession++;
                sessions.put(path, new SessionState(key));
                export(path, new SessionImpl(path));
                return new Pair<>(output, new DBusPath(path));
            }
        }

        @Override
        public Pair<DBusPath, DBusPath> CreateCollection(Map<String, Variant<?>> properties, String alias) {
            record("Service.CreateCollection", SERVICE_PATH);
            String label = stringProperty(properties, de.swiesend.secretservice.interfaces.Collection.LABEL);
            synchronized (lock) {
                // As the spec says: a collection the alias already names is returned, not created.
                if (!alias.isEmpty() && aliases.containsKey(alias)) {
                    return new Pair<>(new DBusPath(aliases.get(alias)), NO_PROMPT);
                }
                // Behind a prompt: gnome-keyring asks for the new keyring's password, KeePassXC
                // for the new database.
                DBusPath prompt = newPrompt(() -> {
                    CollectionState c = newCollection(label);
                    if (!alias.isEmpty()) setAlias(alias, c);
                    return new Variant<>(new DBusPath(c.path));
                });
                return new Pair<>(NO_PROMPT, prompt);
            }
        }

        @Override
        public Pair<List<DBusPath>, List<DBusPath>> SearchItems(Map<String, String> attributes) {
            record("Service.SearchItems", SERVICE_PATH);
            // (unlocked, locked). Reporting a locked item in neither list would be a trap for the
            // next test to use this: it would look like the item does not exist.
            List<DBusPath> unlocked = new ArrayList<>();
            List<DBusPath> locked = new ArrayList<>();
            synchronized (lock) {
                for (CollectionState c : collections.values()) {
                    for (ItemState i : c.items.values()) {
                        if (matches(i, attributes)) {
                            (i.effectivelyLocked() ? locked : unlocked).add(new DBusPath(i.path));
                        }
                    }
                }
            }
            return new Pair<>(unlocked, locked);
        }

        @Override
        public Pair<List<DBusPath>, DBusPath> Unlock(List<DBusPath> objects) {
            List<DBusPath> unlocked = new ArrayList<>();
            List<DBusPath> afterPrompt = new ArrayList<>();
            List<Runnable> onApprove = new ArrayList<>();
            synchronized (lock) {
                for (DBusPath object : objects) {
                    String p = object.getPath();
                    unlockCalls.add(p);
                    record("Service.Unlock", p);
                    CollectionState c = collectionAt(p);
                    ItemState i = c == null ? itemAt(p) : null;
                    if (c != null) {
                        if (!c.locked) {
                            unlocked.add(object);
                        } else if (refuseCollectionUnlock) {
                            // Refused, and no prompt to show for it.
                        } else if (requirePromptForCollectionUnlock) {
                            afterPrompt.add(object);
                            onApprove.add(() -> c.locked = false);
                        } else {
                            c.locked = false;
                            unlocked.add(object);
                        }
                    } else if (i != null) {
                        // The bug this fixture exists for: unlocking the COLLECTION does nothing to
                        // the item, and unlocking the item clears only the item's own lock. A
                        // locked item is released through a prompt, as KeePassXC asks first.
                        if (i.locked) {
                            afterPrompt.add(object);
                            onApprove.add(() -> i.locked = false);
                        } else if (!i.collection.locked) {
                            unlocked.add(object);
                        }
                    }
                }
                if (afterPrompt.isEmpty()) return new Pair<>(unlocked, NO_PROMPT);
                return new Pair<>(unlocked, newPrompt(() -> {
                    onApprove.forEach(Runnable::run);
                    return new Variant<>(afterPrompt, "ao");
                }));
            }
        }

        @Override
        public Pair<List<DBusPath>, DBusPath> Lock(List<DBusPath> objects) {
            List<DBusPath> locked = new ArrayList<>();
            List<DBusPath> afterPrompt = new ArrayList<>();
            List<Runnable> onApprove = new ArrayList<>();
            synchronized (lock) {
                for (DBusPath object : objects) {
                    String p = object.getPath();
                    record("Service.Lock", p);
                    CollectionState c = collectionAt(p);
                    ItemState i = c == null ? itemAt(p) : null;
                    if (c != null) {
                        c.locked = true;
                        locked.add(object);
                    } else if (i != null) {
                        if (requirePromptForItemLock && !i.locked) {
                            afterPrompt.add(object);
                            onApprove.add(() -> i.locked = true);
                        } else {
                            i.locked = true;
                            locked.add(object);
                        }
                    }
                }
                if (afterPrompt.isEmpty()) return new Pair<>(locked, NO_PROMPT);
                return new Pair<>(locked, newPrompt(() -> {
                    onApprove.forEach(Runnable::run);
                    return new Variant<>(afterPrompt, "ao");
                }));
            }
        }

        @Override
        public void LockService() {
            record("Service.LockService", SERVICE_PATH);
            synchronized (lock) {
                for (CollectionState c : collections.values()) c.locked = true;
            }
        }

        @Override
        public DBusPath ChangeLock(DBusPath collection) {
            record("Service.ChangeLock", collection.getPath());
            synchronized (lock) {
                requireCollection(collection.getPath());
                // The user picks the new password in the dialog; nothing here changes.
                return newPrompt(FakeSecretService::noResult);
            }
        }

        @Override
        public Map<DBusPath, Secret> GetSecrets(List<DBusPath> items, DBusPath session) {
            record("Service.GetSecrets", SERVICE_PATH);
            synchronized (lock) {
                SessionState s = session(session);
                Map<DBusPath, Secret> secrets = new LinkedHashMap<>();
                for (DBusPath path : items) {
                    ItemState i = itemAt(path.getPath());
                    // A locked or unknown item is left out instead of failing the whole call.
                    if (i != null && !i.effectivelyLocked()) secrets.put(path, encrypt(s, session, i));
                }
                return secrets;
            }
        }

        @Override
        public DBusPath ReadAlias(String name) {
            record("Service.ReadAlias", SERVICE_PATH);
            synchronized (lock) {
                String path = aliases.get(name);
                return path == null ? NO_PROMPT : new DBusPath(path);
            }
        }

        @Override
        public void SetAlias(String name, DBusPath collection) {
            record("Service.SetAlias", SERVICE_PATH);
            synchronized (lock) {
                if ("/".equals(collection.getPath())) {
                    if (aliases.remove(name) != null) unexport(ALIAS_PREFIX + name);
                } else {
                    setAlias(name, requireCollection(collection.getPath()));
                }
            }
        }

        @Override
        public DBusPath CreateWithMasterPassword(Map<String, Variant<?>> properties, Secret master) {
            record("GnomeKeyring.CreateWithMasterPassword", SERVICE_PATH);
            String label = stringProperty(properties, de.swiesend.secretservice.interfaces.Collection.LABEL);
            synchronized (lock) {
                byte[] password = decrypt(master);
                CollectionState c = newCollection(label);
                c.password = password;
                return new DBusPath(c.path);
            }
        }

        @Override
        public void UnlockWithMasterPassword(DBusPath collection, Secret master) {
            record("GnomeKeyring.UnlockWithMasterPassword", collection.getPath());
            synchronized (lock) {
                CollectionState c = requireCollection(collection.getPath());
                requirePassword(c, decrypt(master));
                c.locked = false;
            }
        }

        @Override
        public void ChangeWithMasterPassword(DBusPath collection, Secret original, Secret master) {
            record("GnomeKeyring.ChangeWithMasterPassword", collection.getPath());
            synchronized (lock) {
                CollectionState c = requireCollection(collection.getPath());
                requirePassword(c, decrypt(original));
                c.password = decrypt(master);
            }
        }

        @Override
        public DBusPath ChangeWithPrompt(DBusPath collection) {
            record("GnomeKeyring.ChangeWithPrompt", collection.getPath());
            synchronized (lock) {
                requireCollection(collection.getPath());
                return newPrompt(FakeSecretService::noResult);
            }
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            record("Properties.Get", SERVICE_PATH + " " + property);
            return (A) all(iface).get(property);
        }

        @Override
        public <A> void Set(String iface, String property, A value) {
            record("Properties.Set", SERVICE_PATH + " " + property);
            throw new PropertyReadOnly("fake: " + property + " is read-only");
        }

        @Override
        public Map<String, Variant<?>> GetAll(String iface) {
            record("Properties.GetAll", SERVICE_PATH);
            return all(iface);
        }

        private Map<String, Variant<?>> all(String iface) {
            Map<String, Variant<?>> properties = new HashMap<>();
            if (!Static.Interfaces.SERVICE.equals(iface)) return properties;
            synchronized (lock) {
                properties.put("Collections", new Variant<>(paths(collections.keySet()), "ao"));
            }
            return properties;
        }

        @Override public String getObjectPath() { return SERVICE_PATH; }
        @Override public boolean isRemote() { return false; }
    }

    private final class CollectionImpl implements WireCollection, Properties {
        private final CollectionState state;
        /** The canonical path, or an alias path that names the same collection. */
        private final String path;

        CollectionImpl(CollectionState state, String path) {
            this.state = state;
            this.path = path;
        }

        @Override
        public DBusPath Delete() {
            record("Collection.Delete", path);
            synchronized (lock) {
                requireExists(state);
                if (requirePromptForDelete) {
                    return newPrompt(() -> {
                        deleteCollection(state);
                        return noResult();
                    });
                }
                deleteCollection(state);
                return NO_PROMPT;
            }
        }

        @Override
        public List<DBusPath> SearchItems(Map<String, String> attributes) {
            record("Collection.SearchItems", path);
            synchronized (lock) {
                requireExists(state);
                List<DBusPath> found = new ArrayList<>();
                for (ItemState i : state.items.values()) {
                    if (matches(i, attributes)) found.add(new DBusPath(i.path));
                }
                return found;
            }
        }

        @Override
        public Pair<DBusPath, DBusPath> CreateItem(Map<String, Variant<?>> properties, Secret secret, boolean replace) {
            record("Collection.CreateItem", path);
            synchronized (lock) {
                requireExists(state);
                if (state.locked) throw new IsLocked("fake: collection " + state.path + " is locked");
                byte[] value = decrypt(secret);
                String label = stringProperty(properties, de.swiesend.secretservice.interfaces.Item.LABEL);
                Map<String, String> attributes = attributesProperty(properties);
                if (replace) {
                    for (ItemState same : state.items.values()) {
                        if (same.attributes.equals(attributes)) {
                            same.label = label;
                            same.secret = value;
                            same.contentType = secret.getContentType();
                            same.modified = now();
                            emit(() -> new de.swiesend.secretservice.interfaces.Collection.ItemChanged(
                                    state.path, new DBusPath(same.path)));
                            return new Pair<>(new DBusPath(same.path), NO_PROMPT);
                        }
                    }
                }
                ItemState item = newItem(state, label, attributes, value, secret.getContentType());
                Variant<?> type = properties.get(ITEM_TYPE);
                if (type != null) item.type = String.valueOf(type.getValue());
                return new Pair<>(new DBusPath(item.path), NO_PROMPT);
            }
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            record("Properties.Get", path + " " + property);
            return (A) all(iface).get(property);
        }

        @Override
        public <A> void Set(String iface, String property, A value) {
            record("Properties.Set", path + " " + property);
            synchronized (lock) {
                requireExists(state);
                if (!Static.Interfaces.COLLECTION.equals(iface)) {
                    throw new UnknownProperty("fake: no property " + property + " on " + iface);
                }
                if (!"Label".equals(property)) {
                    throw new PropertyReadOnly("fake: " + property + " is read-only");
                }
                state.label = String.valueOf(unwrap(value));
                state.modified = now();
                emit(() -> new de.swiesend.secretservice.interfaces.Service.CollectionChanged(
                        SERVICE_PATH, new DBusPath(state.path)));
            }
        }

        @Override
        public Map<String, Variant<?>> GetAll(String iface) {
            record("Properties.GetAll", path);
            return all(iface);
        }

        private Map<String, Variant<?>> all(String iface) {
            Map<String, Variant<?>> properties = new HashMap<>();
            if (!Static.Interfaces.COLLECTION.equals(iface)) return properties;
            synchronized (lock) {
                requireExists(state);
                // The canonical item paths, also through an alias: gnome-keyring serves the default
                // collection at both paths, while its items live only under the canonical one.
                properties.put("Items", new Variant<>(paths(state.items.keySet()), "ao"));
                properties.put("Label", new Variant<>(state.label));
                properties.put("Locked", new Variant<>(state.locked));
                properties.put("Created", new Variant<>(new UInt64(state.created)));
                properties.put("Modified", new Variant<>(new UInt64(state.modified)));
            }
            return properties;
        }

        @Override public String getObjectPath() { return path; }
        @Override public boolean isRemote() { return false; }
    }

    private final class ItemImpl implements WireItem, Properties {
        private final ItemState state;

        ItemImpl(ItemState state) {
            this.state = state;
        }

        @Override
        public DBusPath Delete() {
            record("Item.Delete", state.path);
            synchronized (lock) {
                requireExists(state);
                // Only the collection's lock stands in the way. An item that KeePassXC locks on
                // its own guards its secret; deleting it is a question of its own, which
                // KeePassXC asks with ConfirmDeleteItem -- see setRequirePromptForDelete.
                if (state.collection.locked) {
                    throw new IsLocked("fake: collection " + state.collection.path + " is locked");
                }
                if (requirePromptForDelete) {
                    return newPrompt(() -> {
                        deleteItem(state);
                        return noResult();
                    });
                }
                deleteItem(state);
                return NO_PROMPT;
            }
        }

        @Override
        public Secret GetSecret(DBusPath session) {
            record("Item.GetSecret", state.path);
            synchronized (lock) {
                requireExists(state);
                SessionState s = session(session);
                // What a provider does for a locked item -- including one locked only because its
                // collection is. The client must not get here.
                if (state.effectivelyLocked()) throw new IsLocked("fake: item " + state.path + " is locked");
                return encrypt(s, session, state);
            }
        }

        @Override
        public void SetSecret(Secret secret) {
            record("Item.SetSecret", state.path);
            synchronized (lock) {
                requireExists(state);
                byte[] value = decrypt(secret);
                if (state.effectivelyLocked()) throw new IsLocked("fake: item " + state.path + " is locked");
                state.secret = value;
                state.contentType = secret.getContentType();
                changed(state);
            }
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            record("Properties.Get", state.path + " " + property);
            if (stallItemProperties) {
                // Outlast the client's reply timeout without ever answering.
                try {
                    Thread.sleep(Static.DBus.MAX_DELAY_MILLIS + 1500L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return (A) all(iface).get(property);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> void Set(String iface, String property, A value) {
            record("Properties.Set", state.path + " " + property);
            synchronized (lock) {
                requireExists(state);
                if (!Static.Interfaces.ITEM.equals(iface)) {
                    throw new UnknownProperty("fake: no property " + property + " on " + iface);
                }
                if (state.effectivelyLocked()) throw new IsLocked("fake: item " + state.path + " is locked");
                Object v = unwrap(value);
                switch (property) {
                    case "Label" -> state.label = String.valueOf(v);
                    case "Attributes" -> state.attributes = new HashMap<>((Map<String, String>) v);
                    case "Type" -> state.type = String.valueOf(v);
                    case "Locked", "Created", "Modified" ->
                            throw new PropertyReadOnly("fake: " + property + " is read-only");
                    default -> throw new UnknownProperty("fake: no property " + property + " on " + iface);
                }
                changed(state);
            }
        }

        @Override
        public Map<String, Variant<?>> GetAll(String iface) {
            record("Properties.GetAll", state.path);
            return all(iface);
        }

        private Map<String, Variant<?>> all(String iface) {
            Map<String, Variant<?>> properties = new HashMap<>();
            if (!Static.Interfaces.ITEM.equals(iface)) return properties;
            synchronized (lock) {
                requireExists(state);
                properties.put("Locked", new Variant<>(state.effectivelyLocked()));
                properties.put("Attributes", new Variant<>(new HashMap<>(state.attributes), "a{ss}"));
                properties.put("Label", new Variant<>(state.label));
                properties.put("Type", new Variant<>(state.type));
                properties.put("Created", new Variant<>(new UInt64(state.created)));
                properties.put("Modified", new Variant<>(new UInt64(state.modified)));
            }
            return properties;
        }

        @Override public String getObjectPath() { return state.path; }
        @Override public boolean isRemote() { return false; }
    }

    private final class SessionImpl implements WireSession {
        private final String path;

        SessionImpl(String path) {
            this.path = path;
        }

        @Override
        public void Close() {
            record("Session.Close", path);
            synchronized (lock) {
                if (sessions.remove(path) != null) unexport(path);
            }
        }

        @Override public String getObjectPath() { return path; }
        @Override public boolean isRemote() { return false; }
    }

    private final class PromptImpl implements WirePrompt {
        private final String path;

        PromptImpl(String path) {
            this.path = path;
        }

        @Override
        public void Prompt(String windowId) {
            record("Prompt.Prompt", path);
            synchronized (lock) {
                PromptState p = prompts.get(path);
                if (p == null || p.shown) return;
                p.shown = true;
                promptCalls.add(path);
                // The user answers the dialog they are shown, and only that one.
                complete(p, dismissPrompts);
            }
        }

        @Override
        public void Dismiss() {
            record("Prompt.Dismiss", path);
            synchronized (lock) {
                PromptState p = prompts.get(path);
                if (p != null) complete(p, true);
            }
        }

        @Override public String getObjectPath() { return path; }
        @Override public boolean isRemote() { return false; }
    }

    // ---- store operations; callers hold the lock -------------------------------------------

    private CollectionState newCollection(String label) {
        String base = COLLECTION_PREFIX + pathElement(label);
        String path = base;
        for (int n = 1; collections.containsKey(path); n++) path = base + "_" + n;
        CollectionState c = new CollectionState(path, label);
        collections.put(path, c);
        export(path, new CollectionImpl(c, path));
        String created = path;
        emit(() -> new de.swiesend.secretservice.interfaces.Service.CollectionCreated(
                SERVICE_PATH, new DBusPath(created)));
        return c;
    }

    private ItemState newItem(CollectionState c, String label, Map<String, String> attributes,
                              byte[] secret, String contentType) {
        String path = c.path + "/" + c.nextItem++;
        ItemState item = new ItemState(path, c, label, attributes, secret, contentType);
        c.items.put(path, item);
        c.modified = now();
        export(path, new ItemImpl(item));
        emit(() -> new de.swiesend.secretservice.interfaces.Collection.ItemCreated(c.path, new DBusPath(path)));
        return item;
    }

    private void deleteItem(ItemState item) {
        if (item.collection.items.remove(item.path) == null) return;
        item.collection.modified = now();
        unexport(item.path);
        emit(() -> new de.swiesend.secretservice.interfaces.Collection.ItemDeleted(
                item.collection.path, new DBusPath(item.path)));
    }

    private void deleteCollection(CollectionState c) {
        if (collections.remove(c.path) == null) return;
        for (ItemState item : c.items.values()) unexport(item.path);
        unexport(c.path);
        aliases.entrySet().removeIf(alias -> {
            if (!alias.getValue().equals(c.path)) return false;
            unexport(ALIAS_PREFIX + alias.getKey());
            return true;
        });
        emit(() -> new de.swiesend.secretservice.interfaces.Service.CollectionDeleted(
                SERVICE_PATH, new DBusPath(c.path)));
    }

    private void changed(ItemState item) {
        item.modified = now();
        emit(() -> new de.swiesend.secretservice.interfaces.Collection.ItemChanged(
                item.collection.path, new DBusPath(item.path)));
    }

    private void setAlias(String name, CollectionState c) {
        if (aliases.put(name, c.path) != null) unexport(ALIAS_PREFIX + name);
        exportAlias(name, c);
    }

    private void exportAlias(String name, CollectionState c) {
        // The same collection, addressed as the alias -- how openDefault() reaches it.
        // gnome-keyring serves the default collection at BOTH paths while its items live only
        // under the canonical one. A scope check that compares item paths against the alias
        // prefix goes wrong only through this addressing, so the fake must offer it.
        export(ALIAS_PREFIX + name, new CollectionImpl(c, ALIAS_PREFIX + name));
    }

    private DBusPath newPrompt(Supplier<Variant<?>> onApprove) {
        String path = PROMPT_PREFIX + "p" + nextPrompt++;
        prompts.put(path, new PromptState(path, onApprove));
        export(path, new PromptImpl(path));
        return new DBusPath(path);
    }

    /** Ends a prompt: applies its change unless dismissed, then announces the outcome. */
    private void complete(PromptState p, boolean dismissed) {
        prompts.remove(p.path);
        Variant<?> result = dismissed ? noResult() : p.onApprove.get();
        unexport(p.path);
        emit(() -> new de.swiesend.secretservice.interfaces.Prompt.Completed(p.path, dismissed, result));
    }

    /** The collection at a canonical or an alias path, or null. */
    private CollectionState collectionAt(String path) {
        if (path.startsWith(ALIAS_PREFIX)) {
            String canonical = aliases.get(path.substring(ALIAS_PREFIX.length()));
            return canonical == null ? null : collections.get(canonical);
        }
        return collections.get(path);
    }

    private ItemState itemAt(String path) {
        for (CollectionState c : collections.values()) {
            ItemState item = c.items.get(path);
            if (item != null) return item;
        }
        return null;
    }

    private CollectionState requireCollection(String path) {
        CollectionState c = collectionAt(path);
        if (c == null) throw new NoSuchObject("fake: no collection at " + path);
        return c;
    }

    /** For a call that reached an object deleted while it was on its way. */
    private void requireExists(CollectionState c) {
        if (collections.get(c.path) != c) throw new NoSuchObject("fake: no collection at " + c.path);
    }

    private void requireExists(ItemState item) {
        if (item.collection.items.get(item.path) != item) throw new NoSuchObject("fake: no item at " + item.path);
    }

    private static void requirePassword(CollectionState c, byte[] given) {
        byte[] expected = c.password == null ? new byte[0] : c.password;
        if (!Arrays.equals(expected, given)) throw new org.gnome.keyring.Error.Denied("fake: wrong password");
    }

    private SessionState session(DBusPath path) {
        SessionState s = sessions.get(path.getPath());
        if (s == null) throw new NoSession("fake: no session at " + path.getPath());
        return s;
    }

    private Secret encrypt(SessionState s, DBusPath session, ItemState item) {
        if (s.key() == null) {
            return new Secret(session, new byte[0], item.secret.clone(), item.contentType);
        }
        try {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            Cipher c = Cipher.getInstance(Static.Algorithm.AES_CBC_PKCS5);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(s.key(), Static.Algorithm.AES), new IvParameterSpec(iv));
            return new Secret(session, iv, c.doFinal(item.secret), item.contentType);
        } catch (Exception e) {
            throw new IllegalStateException("fake: could not encrypt", e);
        }
    }

    private byte[] decrypt(Secret secret) {
        SessionState s = session(secret.getSession());
        byte[] value = Static.Utils.toByteArray(secret.getSecretValue());
        if (s.key() == null) return value.clone();
        try {
            Cipher c = Cipher.getInstance(Static.Algorithm.AES_CBC_PKCS5);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(s.key(), Static.Algorithm.AES),
                    new IvParameterSpec(Static.Utils.toByteArray(secret.getSecretParameters())));
            return c.doFinal(value);
        } catch (Exception e) {
            throw new IllegalStateException("fake: could not decrypt", e);
        }
    }

    // ---- helpers ---------------------------------------------------------------------------

    private void record(String call, String target) {
        calls.add(call + " " + target);
    }

    private void export(String path, DBusInterface object) {
        try {
            connection.exportObject(path, object);
        } catch (DBusException e) {
            throw new IllegalStateException("fake: could not export " + path, e);
        }
    }

    private void unexport(String path) {
        connection.unExportObject(path);
    }

    private interface SignalFactory {
        DBusSignal create() throws DBusException;
    }

    private void emit(SignalFactory signal) {
        try {
            signals.execute(() -> {
                try {
                    connection.sendMessage(signal.create());
                } catch (Exception e) {
                    // The test may already have torn the bus down; a signal nobody is waiting for
                    // is not a failure. Throwing here printed stack traces on a passing build,
                    // which the next person to read CI output takes for an error.
                    log("fake: dropped a signal after teardown: " + e.getClass().getName());
                }
            });
        } catch (RejectedExecutionException e) {
            log("fake: dropped a signal after close");
        }
    }

    private static Variant<?> noResult() {
        return new Variant<>("");
    }

    private static boolean matches(ItemState item, Map<String, String> attributes) {
        return item.attributes.entrySet().containsAll(attributes.entrySet());
    }

    private static List<DBusPath> paths(java.util.Collection<String> paths) {
        List<DBusPath> out = new ArrayList<>();
        for (String p : paths) out.add(new DBusPath(p));
        return out;
    }

    private static String stringProperty(Map<String, Variant<?>> properties, String key) {
        Variant<?> v = properties.get(key);
        return v == null ? "" : String.valueOf(v.getValue());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> attributesProperty(Map<String, Variant<?>> properties) {
        Variant<?> v = properties.get(de.swiesend.secretservice.interfaces.Item.ATTRIBUTES);
        return v == null ? new HashMap<>() : new HashMap<>((Map<String, String>) v.getValue());
    }

    private static Object unwrap(Object value) {
        return value instanceof Variant<?> v ? v.getValue() : value;
    }

    /** A path element from a label: D-Bus allows only [A-Za-z0-9_] there. */
    private static String pathElement(String label) {
        String element = label.replaceAll("[^A-Za-z0-9_]", "_");
        return element.isEmpty() ? "collection" : element;
    }

    /** The unsigned big-endian form a provider sends: no leading zero byte for the sign. */
    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private static void log(String message) {
        java.lang.System.err.println(message);
    }

    /** HKDF-SHA256 extract(null salt) + expand(empty info) to 128 bits, as the spec requires. */
    private static byte[] hkdfSha256To128(byte[] ikm) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));   // null salt == 32 zero bytes
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update((byte) 0x01);                                   // empty info, first block
        byte[] okm = mac.doFinal();
        byte[] key = new byte[16];
        java.lang.System.arraycopy(okm, 0, key, 0, 16);
        return key;
    }
}
