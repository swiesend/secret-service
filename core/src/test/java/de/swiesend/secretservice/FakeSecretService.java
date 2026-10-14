package de.swiesend.secretservice;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.interfaces.Properties;
import org.freedesktop.dbus.types.Variant;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;

/**
 * A minimal in-process {@code org.freedesktop.secrets} provider that locks an item
 * <b>individually</b>, which is the condition issue #45 is about and which no provider in CI
 * reproduces: gnome-keyring never locks single items, and the KeePassXC container sets
 * {@code ConfirmAccessItem=false}, switching the behaviour off.
 *
 * <p>The asymmetry is the whole point. {@code Unlock} on the <em>collection</em> path leaves the
 * item locked; only {@code Unlock} on the <em>item</em> path clears it. A client that unlocks just
 * the collection therefore cannot read the secret, exactly as on a real KeePassXC.</p>
 *
 * <p>Only the members the read path touches are implemented, and {@code Item.Delete},
 * {@code Item.SetSecret}, setting the item's properties, {@code Collection.Delete},
 * {@code ReadAlias}, {@code CreateCollection} and {@code CreateItem}. This is a test fixture, not a
 * provider: it does no access control and keeps its secret in a field.</p>
 */
public final class FakeSecretService {

    public static final String BUS_NAME = "org.freedesktop.secrets";
    public static final String SERVICE_PATH = "/org/freedesktop/secrets";
    public static final String COLLECTION_PATH = "/org/freedesktop/secrets/collection/fake";
    /** The client resolves a collection by label, so the Label property must match this. */
    public static final String COLLECTION_LABEL = "fake";
    public static final String ITEM_PATH = COLLECTION_PATH + "/1";
    public static final String SESSION_PATH = "/org/freedesktop/secrets/session/fake";
    public static final String PROMPT_PATH = "/org/freedesktop/secrets/prompt/fake";

    /** What the fake item holds. */
    public static final String SECRET_VALUE = "the-locked-secret";

    /**
     * RFC 2409, section 6.2: the prime of the group that the specification prescribes. The fake's
     * own copy, as a provider has one, independent of the library's.
     */
    private static final BigInteger SECOND_OAKLEY_GROUP_PRIME = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
                    + "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
                    + "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
                    + "FFFFFFFFFFFFFFFF", 16);

    // ---- wire interfaces -------------------------------------------------------------------
    // The library's own de.swiesend.secretservice.interfaces.* declare Optional<...> returns, which
    // are not valid D-Bus types; they exist to be used as client proxies, with the marshalling done
    // by MessageHandler. To EXPORT an object we need signatures dbus-java can serialise, so they are
    // redeclared here. Pair already extends org.freedesktop.dbus.Tuple with @Position, so it maps to
    // multiple out-arguments as-is.

    @DBusInterfaceName(Static.Interfaces.SERVICE)
    public interface WireService extends DBusInterface {
        Pair<Variant<byte[]>, DBusPath> OpenSession(String algorithm, Variant<?> input);
        Pair<List<DBusPath>, DBusPath> Unlock(List<DBusPath> objects);
        Pair<List<DBusPath>, DBusPath> Lock(List<DBusPath> objects);
        Pair<List<DBusPath>, List<DBusPath>> SearchItems(Map<String, String> attributes);
        Pair<DBusPath, DBusPath> CreateCollection(Map<String, Variant<?>> properties, String alias);
        DBusPath ReadAlias(String name);
    }

    @DBusInterfaceName(Static.Interfaces.COLLECTION)
    public interface WireCollection extends DBusInterface {
        List<DBusPath> SearchItems(Map<String, String> attributes);
        Pair<DBusPath, DBusPath> CreateItem(Map<String, Variant<?>> properties, Secret secret, boolean replace);
        DBusPath Delete();
    }

    @DBusInterfaceName(Static.Interfaces.ITEM)
    public interface WireItem extends DBusInterface {
        DBusPath Delete();
        WireSecret GetSecret(DBusPath session);
        void SetSecret(Secret secret);
    }

    /**
     * A secret as it goes over the bus, {@code (oayays)}, with the content type as given. The
     * library's {@link Secret} would rewrite a content type it cannot parse, and the client would
     * never see it.
     */
    public static final class WireSecret extends org.freedesktop.dbus.Struct {
        @org.freedesktop.dbus.annotations.Position(0)
        private final DBusPath session;
        @org.freedesktop.dbus.annotations.Position(1)
        private final byte[] parameters;
        @org.freedesktop.dbus.annotations.Position(2)
        private final byte[] value;
        @org.freedesktop.dbus.annotations.Position(3)
        private final String contentType;

        public WireSecret(DBusPath session, byte[] parameters, byte[] value, String contentType) {
            this.session = session;
            this.parameters = parameters;
            this.value = value;
            this.contentType = contentType;
        }
    }

    @DBusInterfaceName(Static.Interfaces.SESSION)
    public interface WireSession extends DBusInterface {
        void Close();
    }


    // ---- state -----------------------------------------------------------------------------

    private final DBusConnection connection;
    private volatile boolean itemLocked;
    private volatile boolean collectionLocked;
    private volatile boolean dismissPrompts;

    /** Every path passed to Unlock, in call order -- what the tests assert on. */
    private final List<String> unlockCalls = Collections.synchronizedList(new ArrayList<>());

    // volatile like the other mutable fields: written in OpenSession and read in GetSecret,
    // which dbus-java may dispatch on different threads of its receiving pool.
    private volatile byte[] sessionKey;
    /** The pending prompt emitter, so a test can wait for it instead of racing it. */
    private volatile Thread promptThread;

    public FakeSecretService(DBusConnection connection, boolean itemLocked) {
        this.connection = connection;
        this.itemLocked = itemLocked;
    }

    /** Paths that {@code Unlock} was called with, in order. */
    public List<String> unlockCalls() {
        return List.copyOf(unlockCalls);
    }

    /** Labels that {@code CreateCollection} was called with, in order. */
    public List<String> createCollectionCalls() {
        return List.copyOf(createCollectionCalls);
    }

    private final List<String> createCollectionCalls = Collections.synchronizedList(new ArrayList<>());

    /**
     * Claims another bus name on the fake's connection, as gnome-keyring owns {@code org.gnome.keyring}
     * on the connection that serves {@code org.freedesktop.secrets}.
     */
    public void requestBusName(String name) throws Exception {
        connection.requestBusName(name);
    }

    /** Makes the prompt come back dismissed, as if the user had refused it. */
    public void setDismissPrompts(boolean dismiss) {
        this.dismissPrompts = dismiss;
    }

    /** Locks the collection, as a provider does when the keyring times out or the user locks it. */
    public void lockCollection() { collectionLocked = true; }

    /**
     * Refuses to unlock the collection, as happens when the user dismisses the keyring prompt, the
     * stored password is wrong, or prompting is disabled. This is the state in which a per-item
     * unlock attempt would raise a SECOND prompt.
     */
    public void setRefuseCollectionUnlock(boolean refuse) { this.refuseCollectionUnlock = refuse; }
    private volatile boolean refuseCollectionUnlock;

    /**
     * Makes item Lock/Unlock require a prompt that would <b>succeed</b>. Without this the fake
     * completes those operations inline, so a test cannot tell "the client refused to prompt" from
     * "the operation failed anyway" -- both give the same answer. With it, the operation succeeds
     * when prompting is allowed and fails when it is not, which is the difference under test.
     */
    public void setRequirePromptForItemOps(boolean require) { this.requirePromptForItemOps = require; }
    private volatile boolean requirePromptForItemOps;

    /**
     * Makes locking the collection require a prompt, as KeePassXC does: Lock answers with a prompt
     * path and locks only when {@link #approvePendingPrompt()} answers it.
     */
    public void setRequirePromptForCollectionLock(boolean require) { this.requirePromptForCollectionLock = require; }
    private volatile boolean requirePromptForCollectionLock;

    /**
     * Makes unlocking the locked collection require a prompt, as gnome-keyring's password dialog
     * does: Unlock answers with a prompt path and unlocks only when {@link #approvePendingPrompt()}
     * answers it.
     */
    public void setRequirePromptForCollectionUnlock(boolean require) { this.requirePromptForCollectionUnlock = require; }
    private volatile boolean requirePromptForCollectionUnlock;

    public boolean isCollectionLocked() {
        return collectionLocked;
    }

    /** Makes {@code Service.SearchItems} reply only after {@code delay}, as an overloaded provider does. */
    public void setSearchReplyDelay(java.time.Duration delay) { this.searchReplyDelay = delay; }
    private volatile java.time.Duration searchReplyDelay = java.time.Duration.ZERO;

    /** State change the outstanding Lock prompt would authorise; applied only on approval. */
    private volatile Runnable pendingApproval;

    /**
     * Answers the outstanding Lock prompt affirmatively: applies the change it authorises, then
     * emits Completed. Lock uses explicit approval rather than a timer, because a timer applies the
     * change whether or not the client ever engaged with the prompt, which makes "the client
     * declined to prompt" indistinguishable from "it happened anyway".
     */
    public void approvePendingPrompt() {
        Runnable apply = pendingApproval;
        pendingApproval = null;
        if (apply != null) apply.run();
        Variant<?> result = pendingResult;
        pendingResult = null;
        emitCompletedLater(false, () -> { }, result == null ? new Variant<>(new ArrayList<DBusPath>(), "ao") : result);
    }

    /** What the outstanding prompt answers with, when it is not an empty list of paths. */
    private volatile Variant<?> pendingResult;

    /** Where the fake reports an item created through its CreateItem prompt. */
    public static final String CREATED_ITEM_PATH = COLLECTION_PATH + "/2";

    /** Labels that {@code CreateItem} was called with, in order. */
    public List<String> createItemCalls() {
        return List.copyOf(createItemCalls);
    }

    private final List<String> createItemCalls = Collections.synchronizedList(new ArrayList<>());

    /** Whether a Lock prompt is outstanding, so a test can wait for it instead of racing it. */
    public boolean hasPendingPrompt() { return pendingApproval != null; }

    /** Waits for any pending prompt emission, so teardown does not race it. */
    public void awaitPendingPrompt() {
        Thread t = promptThread;
        if (t == null) return;
        try {
            t.join(5_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void log(String message) {
        java.lang.System.err.println(message);
    }

    public boolean isItemLocked() {
        return itemLocked;
    }

    /** Whether the store holds an item at {@code path}. */
    public boolean hasItem(String path) {
        return ITEM_PATH.equals(path) && !itemDeleted;
    }

    private volatile boolean itemDeleted;

    /** The item properties that {@code Set} changed, in call order. */
    public List<String> itemPropertySets() {
        return List.copyOf(itemPropertySets);
    }

    private final List<String> itemPropertySets = Collections.synchronizedList(new ArrayList<>());

    /** Makes {@code Set} on the item fail, as a provider refuses to change an item it keeps locked. */
    public void setRefuseItemPropertyChanges(boolean refuse) { this.refuseItemPropertyChanges = refuse; }
    private volatile boolean refuseItemPropertyChanges;

    /** How often {@code SetSecret} was called on the item. */
    public int setSecretCalls() {
        return setSecretCalls.get();
    }

    /**
     * Points the {@code default} alias at {@code path}, as a provider names its default collection.
     * Without it, {@code ReadAlias} answers "/", for no such collection.
     */
    public void setDefaultAlias(String path) { this.defaultAlias = path; }
    private volatile String defaultAlias;

    /**
     * The content type that {@code GetSecret} gives the secret, as the application that stored it
     * chose it. The specification's own default, with its unusual spelling, unless set.
     */
    public void setSecretContentType(String contentType) { this.secretContentType = contentType; }
    private volatile String secretContentType = "text/plain; charset=utf8";

    /**
     * The secret that {@code GetSecret} hands out instead of {@link #SECRET_VALUE}: {@code value},
     * encoded in {@code encoding}, under {@code contentType}.
     */
    public void setStoredSecret(String value, java.nio.charset.Charset encoding, String contentType) {
        this.secretValue = value;
        this.secretEncoding = encoding;
        this.secretContentType = contentType;
    }

    private volatile String secretValue = SECRET_VALUE;
    private volatile java.nio.charset.Charset secretEncoding = StandardCharsets.UTF_8;

    /** How often {@code Delete} was called on the collection. */
    public int collectionDeleteCalls() {
        return collectionDeleteCalls.get();
    }

    private final java.util.concurrent.atomic.AtomicInteger collectionDeleteCalls = new java.util.concurrent.atomic.AtomicInteger();

    private final java.util.concurrent.atomic.AtomicInteger setSecretCalls = new java.util.concurrent.atomic.AtomicInteger();

    public void export() throws Exception {
        connection.exportObject(SERVICE_PATH, new ServiceImpl());
        connection.exportObject(COLLECTION_PATH, new CollectionImpl());
        connection.exportObject(ITEM_PATH, new ItemImpl());
        connection.exportObject(SESSION_PATH, new SessionImpl());
        connection.requestBusName(BUS_NAME);
    }

    // ---- implementations -------------------------------------------------------------------

    private final class ServiceImpl implements WireService, Properties {

        @Override
        public Pair<Variant<byte[]>, DBusPath> OpenSession(String algorithm, Variant<?> input) {
            // Mirror of TransportEncryption's client half: RFC 2409 Second Oakley Group, HKDF-SHA256
            // with a null salt and empty info, AES-128. The client cannot negotiate a plain session,
            // so the fake has to do the real exchange.
            try {
                byte[] clientY = Static.Utils.toByteArray(input.getValue());
                DHParameterSpec params = new DHParameterSpec(SECOND_OAKLEY_GROUP_PRIME, BigInteger.valueOf(2), 1024);

                KeyPairGenerator gen = KeyPairGenerator.getInstance("DiffieHellman");
                gen.initialize(params);
                KeyPair ours = gen.generateKeyPair();

                DHPublicKey theirs = (DHPublicKey) KeyFactory.getInstance("DiffieHellman")
                        .generatePublic(new DHPublicKeySpec(
                                new BigInteger(1, clientY), params.getP(), params.getG()));

                KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
                ka.init(ours.getPrivate());
                ka.doPhase(theirs, true);
                sessionKey = hkdfSha256To128(ka.generateSecret());

                BigInteger ourY = ((DHPublicKey) ours.getPublic()).getY();
                return new Pair<>(new Variant<>(ourY.toByteArray()), new DBusPath(SESSION_PATH));
            } catch (Exception e) {
                throw new IllegalStateException("fake OpenSession failed", e);
            }
        }

        @Override
        public Pair<List<DBusPath>, DBusPath> Unlock(List<DBusPath> objects) {
            for (DBusPath p : objects) unlockCalls.add(p.getPath());
            // The bug this fixture exists for: unlocking the COLLECTION does nothing to the item.
            boolean itemRequested = objects.stream().anyMatch(p -> ITEM_PATH.equals(p.getPath()));
            if (!itemRequested) {
                if (refuseCollectionUnlock) {
                    return new Pair<>(new ArrayList<DBusPath>(), new DBusPath("/"));
                }
                if (requirePromptForCollectionUnlock && collectionLocked) {
                    // Unlocked only when a test answers the prompt, as for the Lock prompts.
                    pendingApproval = () -> collectionLocked = false;
                    return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(PROMPT_PATH));
                }
                // A collection-level unlock succeeds immediately and, crucially, does NOT touch the
                // item. That asymmetry is the bug under test.
                collectionLocked = false;
                return new Pair<>(new ArrayList<>(objects), new DBusPath("/"));
            }
            if (dismissPrompts) {
                // A REAL prompt path, and a Completed(dismissed=true) to go with it. Answering "/"
                // instead would leave the client no prompt to await -- so every test would hit the
                // "no prompt result" path, and the dismissal branch would have no coverage at all.
                //
                // No Prompt object is exported: declaring @DBusInterfaceName for
                // org.freedesktop.Secret.Prompt registers a JVM-wide interface->class mapping that
                // stops dbus-java constructing the library's own Prompt.Completed. The client's
                // Prompt() method call therefore fails harmlessly; only the signal matters.
                emitCompletedLater(true);
                return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(PROMPT_PATH));
            }
            if (requirePromptForItemOps) {
                // Unlocked only when the prompt is answered -- see emitCompletedLater. Doing it
                // here would mean a client that declines to prompt still sees the item unlocked.
                emitCompletedLater(false, () -> itemLocked = false);
                return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(PROMPT_PATH));
            }
            itemLocked = false;
            return new Pair<>(new ArrayList<>(objects), new DBusPath("/"));
        }

        @Override
        public Pair<List<DBusPath>, DBusPath> Lock(List<DBusPath> objects) {
            boolean itemRequested = objects.stream().anyMatch(p -> ITEM_PATH.equals(p.getPath()));
            if (itemRequested && requirePromptForItemOps && !itemLocked) {
                // Only the item goes behind a prompt, and only when it is not already locked;
                // every other case falls through, as in Unlock. Nothing is scheduled: the item is
                // locked only when a test calls approvePendingPrompt(), so a client that declines
                // to prompt leaves it unlocked, as a real provider does when Prompt() is never
                // called.
                pendingApproval = () -> itemLocked = true;
                return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(PROMPT_PATH));
            }
            boolean collectionRequested = objects.stream().anyMatch(p -> COLLECTION_PATH.equals(p.getPath()));
            if (collectionRequested && requirePromptForCollectionLock && !collectionLocked) {
                // As for the item above: locked only when a test answers the prompt.
                pendingApproval = () -> collectionLocked = true;
                return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(PROMPT_PATH));
            }
            for (DBusPath p : objects) {
                if (ITEM_PATH.equals(p.getPath())) itemLocked = true;
                if (COLLECTION_PATH.equals(p.getPath())) collectionLocked = true;
            }
            return new Pair<>(new ArrayList<>(objects), new DBusPath("/"));
        }

        @Override
        public Pair<List<DBusPath>, List<DBusPath>> SearchItems(Map<String, String> attributes) {
            if (!searchReplyDelay.isZero()) {
                try {
                    Thread.sleep(searchReplyDelay.toMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            // (unlocked, locked). Reporting the item in neither list when it is locked would be a
            // trap for the next test to use this: it would look like the item does not exist.
            List<DBusPath> item = new ArrayList<>(List.of(new DBusPath(ITEM_PATH)));
            // Same condition as the Locked property and GetSecret below: a fixture that reports an
            // item locked in one place and hands out its plaintext in another teaches the next test
            // something no real provider does.
            return (itemLocked || collectionLocked)
                    ? new Pair<>(new ArrayList<DBusPath>(), item)
                    : new Pair<>(item, new ArrayList<DBusPath>());
        }

        @Override
        public Pair<DBusPath, DBusPath> CreateCollection(Map<String, Variant<?>> properties, String alias) {
            Variant<?> label = properties.get(Collection.LABEL);
            createCollectionCalls.add(label == null ? "" : String.valueOf(label.getValue()));
            // Through a prompt, as a provider without gnome-keyring's password interface creates a
            // collection: the user sets the password there. The user cancels it here, so nothing is
            // created; the tests need to see that the request was made, not a new collection.
            emitCompletedLater(true);
            return new Pair<>(new DBusPath("/"), new DBusPath(PROMPT_PATH));
        }

        @Override
        public DBusPath ReadAlias(String name) {
            String target = "default".equals(name) ? defaultAlias : null;
            return new DBusPath(target == null ? "/" : target);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            if ("Collections".equals(property)) {
                return (A) new Variant<>(new ArrayList<>(List.of(new DBusPath(COLLECTION_PATH))), "ao");
            }
            throw new IllegalArgumentException("fake: unsupported property " + property);
        }

        @Override public <A> void Set(String iface, String property, A value) { }
        @Override public Map<String, Variant<?>> GetAll(String iface) { return Map.of(); }
        @Override public String getObjectPath() { return SERVICE_PATH; }
        @Override public boolean isRemote() { return false; }
    }

    private final class CollectionImpl implements WireCollection, Properties {
        @Override
        public List<DBusPath> SearchItems(Map<String, String> attributes) {
            return List.of(new DBusPath(ITEM_PATH));
        }

        @Override
        public Pair<DBusPath, DBusPath> CreateItem(Map<String, Variant<?>> properties, Secret secret, boolean replace) {
            Variant<?> label = properties.get(Item.LABEL);
            createItemCalls.add(label == null ? "" : String.valueOf(label.getValue()));
            // Through a prompt, as KeePassXC creates every item. The fake stores nothing: answering
            // the prompt reports CREATED_ITEM_PATH in its result, where KeePassXC reports the item.
            pendingApproval = () -> { };
            pendingResult = new Variant<>(new DBusPath(CREATED_ITEM_PATH), "o");
            return new Pair<>(new DBusPath("/"), new DBusPath(PROMPT_PATH));
        }

        @Override
        public DBusPath Delete() {
            // Counted, not carried out: the collection and its item stay for the rest of the test.
            collectionDeleteCalls.incrementAndGet();
            return new DBusPath("/");
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            switch (property) {
                case "Locked":  return (A) Boolean.valueOf(collectionLocked);
                case "Items":   return (A) new Variant<>(new ArrayList<>(List.of(new DBusPath(ITEM_PATH))), "ao");
                case "Label":   return (A) COLLECTION_LABEL;
                default: throw new IllegalArgumentException("fake: unsupported property " + property);
            }
        }

        @Override public <A> void Set(String iface, String property, A value) { }
        @Override public Map<String, Variant<?>> GetAll(String iface) { return Map.of(); }
        @Override public String getObjectPath() { return COLLECTION_PATH; }
        @Override public boolean isRemote() { return false; }
    }

    private final class ItemImpl implements WireItem, Properties {
        @Override
        public DBusPath Delete() {
            // Deleted at once, answering "/" for "no prompt necessary", as gnome-keyring does. The
            // fake does not own org.gnome.keyring, so the client sees a provider other than
            // gnome-keyring giving that answer.
            itemDeleted = true;
            connection.unExportObject(ITEM_PATH);
            return new DBusPath("/");
        }

        @Override
        public WireSecret GetSecret(DBusPath session) {
            if (itemLocked || collectionLocked) {
                // What a provider does for a locked item -- including one locked only because its
                // collection is. The client must not get here.
                throw new IllegalStateException("fake: item is locked");
            }
            try {
                byte[] iv = new byte[16];
                new SecureRandom().nextBytes(iv);
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), new IvParameterSpec(iv));
                byte[] ct = c.doFinal(secretValue.getBytes(secretEncoding));
                return new WireSecret(new DBusPath(SESSION_PATH), iv, ct, secretContentType);
            } catch (Exception e) {
                throw new IllegalStateException("fake GetSecret failed", e);
            }
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            switch (property) {
                // gnome-keyring reports an item as locked whenever its collection is locked, so
                // the fake does too when asked to. This is what makes the regression reproducible.
                case "Locked":     return (A) Boolean.valueOf(itemLocked || collectionLocked);
                case "Attributes": return (A) new Variant<>(new HashMap<String, String>(), "a{ss}");
                case "Label":      return (A) "fake-item";
                default: throw new IllegalArgumentException("fake: unsupported property " + property);
            }
        }

        @Override
        public void SetSecret(Secret secret) {
            setSecretCalls.incrementAndGet();
        }

        @Override
        public <A> void Set(String iface, String property, A value) {
            // Changes nothing: the tests need to see which properties were set, not the new values.
            if (refuseItemPropertyChanges) throw new IllegalStateException("fake: the item is locked");
            itemPropertySets.add(property);
        }

        @Override public Map<String, Variant<?>> GetAll(String iface) { return Map.of(); }
        @Override public String getObjectPath() { return ITEM_PATH; }
        @Override public boolean isRemote() { return false; }
    }

    private final class SessionImpl implements WireSession {
        @Override public void Close() { }
        @Override public String getObjectPath() { return SESSION_PATH; }
        @Override public boolean isRemote() { return false; }
    }


    /**
     * Emits {@code Prompt.Completed} shortly after Unlock returns, as a provider does once the user
     * has answered. The delay lets the client arm its signal handler first -- it does that inside
     * Prompt.await, which it only reaches after Unlock has returned.
     */
    private void emitCompletedLater(boolean dismissed) {
        emitCompletedLater(dismissed, () -> { });
    }

    /** @param onAnswered applied when the prompt is answered, before the signal goes out. */
    private void emitCompletedLater(boolean dismissed, Runnable onAnswered) {
        emitCompletedLater(dismissed, onAnswered, new Variant<>(new ArrayList<DBusPath>(), "ao"));
    }

    /** @param result the prompt's result, which depends on the operation that asked for it */
    private void emitCompletedLater(boolean dismissed, Runnable onAnswered, Variant<?> result) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(150);
                if (!dismissed) onAnswered.run();
                connection.sendMessage(new de.swiesend.secretservice.interfaces.Prompt.Completed(
                        PROMPT_PATH, dismissed, result));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                // The test may already have torn the bus down; a Completed nobody is waiting for is
                // not a failure. Throwing here printed stack traces on a passing build, which the
                // next person to read CI output takes for an error.
                log("fake: dropped a Completed signal after teardown: " + e.getClass().getName());
            }
        }, "fake-prompt");
        t.setDaemon(true);
        promptThread = t;
        t.start();
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
