package de.swiesend.secretservice;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.interfaces.Properties;
import org.freedesktop.dbus.types.Variant;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

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
 * provider: it does no access control and keeps its secret in a field. A test can add a second
 * item, with a lock of its own, for the reads of several items.</p>
 *
 * <p>Each prompt it hands out has a path of its own and is an object on the bus, so the client's
 * {@code Prompt} and {@code Dismiss} reach the fake, which records them. The prompt that unlocks
 * the collection shows its dialog as gnome-keyring does: once the client calls {@code Prompt}, and
 * one dialog at a time.</p>
 *
 * <p>The fake follows the specification where {@link ProviderBug} lists a provider's bug, until a
 * test makes it {@link #reproduce} that bug.</p>
 */
public final class FakeSecretService {

    public static final String BUS_NAME = "org.freedesktop.secrets";
    public static final String SERVICE_PATH = "/org/freedesktop/secrets";
    public static final String COLLECTION_PATH = "/org/freedesktop/secrets/collection/fake";
    /**
     * The client resolves a collection by label, so the Label property must match this. It appears
     * in no object path, so a test can tell from a log whether the label reached it.
     */
    public static final String COLLECTION_LABEL = "Fake Keyring";
    public static final String ITEM_PATH = COLLECTION_PATH + "/1";
    /** The item that {@link #addSecondItem(boolean)} adds. */
    public static final String SECOND_ITEM_PATH = COLLECTION_PATH + "/3";
    public static final String SESSION_PATH = "/org/freedesktop/secrets/session/fake";
    /** A prompt's path that the fake never hands out, for the signals that a test sends itself. */
    public static final String PROMPT_PATH = "/org/freedesktop/secrets/prompt/fake";
    /**
     * Where the fake's own prompts are: "u" and a number for one that unlocks the collection, "p"
     * and a number for any other, as gnome-keyring names its prompts.
     */
    private static final String PROMPT_PREFIX = "/org/freedesktop/secrets/prompt/";

    /** What the fake item holds. */
    public static final String SECRET_VALUE = "the-locked-secret";
    /** What the second item holds. */
    public static final String SECOND_SECRET_VALUE = "the-second-secret";

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
        Pair<DBusPath, DBusPath> CreateItem(Map<String, Variant<?>> properties, WireSecret secret, boolean replace);
        DBusPath Delete();
    }

    @DBusInterfaceName(Static.Interfaces.ITEM)
    public interface WireItem extends DBusInterface {
        DBusPath Delete();
        WireSecret GetSecret(DBusPath session);
        void SetSecret(WireSecret secret);
    }

    /**
     * A secret as it goes over the bus, {@code (oayays)}, with the content type as given. The
     * library's {@link Secret} would rewrite a content type it cannot parse: the client would never
     * see it, and the fake would not see the one the client sends.
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

        public String contentType() {
            return contentType;
        }
    }

    @DBusInterfaceName(Static.Interfaces.SESSION)
    public interface WireSession extends DBusInterface {
        void Close();
    }

    /**
     * Without {@code @DBusInterfaceName}, unlike the interfaces above. dbus-java keeps one JVM-wide
     * map from an annotated D-Bus interface name to the Java interface last exported under it, and
     * builds each incoming signal of that interface as that Java interface's nested class: with
     * org.freedesktop.Secret.Prompt mapped here, the client could no longer build its
     * Prompt.Completed, in this test and in every later one in the JVM. dbus-java dispatches an
     * incoming call by member name and signature, so the client's Prompt and Dismiss reach this
     * interface all the same.
     */
    public interface WirePrompt extends DBusInterface {
        void Prompt(String windowId);
        void Dismiss();
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

    /**
     * Makes the fake behave as a provider with these bugs does; it follows the specification there
     * otherwise. A bug that the fake always shows needs no call.
     *
     * @throws UnsupportedOperationException for a bug that the fake does not reproduce
     */
    public void reproduce(ProviderBug... bugs) {
        for (ProviderBug bug : bugs) {
            if (bug.fake == ProviderBug.Fake.NOT_REPRODUCED) {
                throw new UnsupportedOperationException(
                        bug + " is not reproduced by the fake; its description says why");
            }
            reproduced.add(bug);
        }
    }

    private final java.util.Set<ProviderBug> reproduced = java.util.concurrent.ConcurrentHashMap.newKeySet();

    private boolean reproduces(ProviderBug bug) {
        return reproduced.contains(bug);
    }

    /** Paths that {@code Unlock} was called with, in order. */
    public List<String> unlockCalls() {
        return List.copyOf(unlockCalls);
    }

    /** The paths of each {@code Unlock} call, one list per call, in call order. */
    public List<List<String>> unlockRequests() {
        return List.copyOf(unlockRequests);
    }

    private final List<List<String>> unlockRequests = Collections.synchronizedList(new ArrayList<>());

    /**
     * Adds a second item to the collection, locked on its own or not, as KeePassXC locks each item
     * for a client until the user confirms its access. It holds {@link #SECOND_SECRET_VALUE}.
     */
    public void addSecondItem(boolean locked) throws Exception {
        secondItemLocked = locked;
        connection.exportObject(SECOND_ITEM_PATH, new ItemImpl(SECOND_ITEM_PATH));
    }

    /** Null while there is no second item. */
    private volatile Boolean secondItemLocked;

    public boolean isSecondItemLocked() {
        return Boolean.TRUE.equals(secondItemLocked);
    }

    /** How many prompts {@code Unlock} gave for items. */
    public int itemUnlockPrompts() {
        return itemUnlockPrompts.get();
    }

    private final java.util.concurrent.atomic.AtomicInteger itemUnlockPrompts = new java.util.concurrent.atomic.AtomicInteger();

    /**
     * Makes {@code Unlock} of several items unlock the first at once and give a prompt for the rest,
     * an answer that the specification allows: the prompt unlocks the remaining objects.
     */
    public void setUnlockFirstItemWithoutPrompt(boolean partly) { this.unlockFirstItemWithoutPrompt = partly; }
    private volatile boolean unlockFirstItemWithoutPrompt;

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

    /** State change the outstanding Lock or CreateItem prompt would authorise; applied only on approval. */
    private volatile Runnable pendingApproval;
    /** The prompt that {@link #pendingApproval} belongs to. */
    private volatile FakePrompt pendingPrompt;

    /**
     * Answers the open prompt affirmatively, as the user does: the unlock dialog on the screen, which
     * unlocks the collection, or else the outstanding Lock or CreateItem prompt, whose change it
     * applies before Completed goes out. Those prompts use explicit approval rather than a timer,
     * because a timer applies the change whether or not the client ever engaged with the prompt,
     * which makes "the client declined to prompt" indistinguishable from "it happened anyway".
     */
    public void approvePendingPrompt() {
        synchronized (promptLock) {
            if (answerDismissedDialog(true)) return;
            FakePrompt dialog = unlockInProgress();
            if (dialog != null) {
                unlockDialogs.removeFirst();
                collectionLocked = false;
                complete(dialog, false, unlockedCollection());
                showNextDialog();
                return;
            }
        }
        FakePrompt prompt = pendingPrompt;
        Runnable apply = pendingApproval;
        Variant<?> result = pendingResult;
        clearPendingApproval();
        if (prompt == null) return;
        if (apply != null) apply.run();
        emitCompletedLater(prompt, false, () -> { }, result == null ? noResult() : result);
    }

    /**
     * Refuses the open prompt, as the user does who cancels its dialog: the unlock dialog on the
     * screen, after which the next unlock prompt that waits shows its own, or else the outstanding
     * Lock or CreateItem prompt.
     */
    public void refusePendingPrompt() {
        synchronized (promptLock) {
            if (answerDismissedDialog(false)) return;
            FakePrompt dialog = unlockInProgress();
            if (dialog != null) {
                unlockDialogs.removeFirst();
                complete(dialog, true, noResult());
                showNextDialog();
                return;
            }
        }
        FakePrompt prompt = pendingPrompt;
        clearPendingApproval();
        if (prompt != null) emitCompletedLater(prompt, true, () -> { }, noResult());
    }

    /**
     * Hands out a prompt that completes only when a test approves or refuses it, and applies
     * {@code change} on approval.
     *
     * @param result what Completed carries on approval, or null for an empty list of paths
     */
    private FakePrompt awaitApproval(Runnable change, Variant<?> result) {
        FakePrompt prompt = newPrompt(false);
        pendingPrompt = prompt;
        pendingResult = result;
        pendingApproval = change;
        return prompt;
    }

    private void clearPendingApproval() {
        pendingApproval = null;
        pendingPrompt = null;
        pendingResult = null;
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

    /** The names of the properties that each {@code CreateItem} call was given, in call order. */
    public List<java.util.Set<String>> createItemPropertyNames() {
        return List.copyOf(createItemPropertyNames);
    }

    private final List<java.util.Set<String>> createItemPropertyNames = Collections.synchronizedList(new ArrayList<>());

    /**
     * Whether a prompt waits for the user, so a test can wait for it instead of racing it: an unlock
     * dialog on the screen, or an outstanding Lock or CreateItem prompt.
     */
    public boolean hasPendingPrompt() {
        synchronized (promptLock) {
            if (dismissedDialog != null || unlockInProgress() != null) return true;
        }
        return pendingApproval != null;
    }

    /**
     * Whether the fake has aborted, as gnome-keyring does on some dismissed unlock prompts: it
     * answers no call from then on.
     */
    public boolean hasAborted() {
        return aborted;
    }

    private volatile boolean aborted;

    /** Fails the call once the fake has aborted: the daemon is gone. */
    private void alive() {
        if (aborted) throw new org.freedesktop.dbus.errors.ServiceUnknown("fake: the daemon has aborted");
    }

    /** Whether the items are off the bus, as KeePassXC takes those of a locked database off it. */
    private boolean itemsHidden() {
        return collectionLocked && reproduces(ProviderBug.KEEPASSXC_HIDES_THE_ITEMS_OF_A_LOCKED_DATABASE);
    }

    /** Whether a search for {@code attributes} finds nothing, whatever the collection holds. */
    private boolean findsNothing(Map<String, String> attributes) {
        return itemsHidden() || attributes.isEmpty() && reproduces(ProviderBug.KEEPASSXC_AN_EMPTY_SEARCH_FINDS_NOTHING);
    }

    /** Refuses a content type other than exactly the two that oo7 0.6.0 takes. */
    private void checkContentType(String contentType) {
        if (reproduces(ProviderBug.OO7_REFUSES_A_CONTENT_TYPE_WITH_PARAMETERS)
                && !List.of("text/plain", "application/octet-stream").contains(contentType)) {
            throw new org.freedesktop.dbus.exceptions.DBusExecutionException(
                    "fake: oo7 refuses the content type " + contentType);
        }
    }

    /** The paths that {@code Lock} was called with, in call order. */
    public List<String> lockCalls() {
        return List.copyOf(lockCalls);
    }

    private final List<String> lockCalls = Collections.synchronizedList(new ArrayList<>());

    /**
     * Lets the calls return that the fake does not answer, as oo7 answers none after a panic, so
     * that a test's teardown does not wait for them. The fixture calls it when it stops.
     */
    public void release() {
        released.countDown();
    }

    private final java.util.concurrent.CountDownLatch released = new java.util.concurrent.CountDownLatch(1);

    /** Answers the call never, until {@link #release()}: the client's wait for the reply runs out. */
    private void neverAnswer() {
        try {
            released.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        throw new org.freedesktop.dbus.exceptions.DBusExecutionException("fake: the handler panicked");
    }

    /** The paths of the prompts that the client called {@code Prompt} on, in call order. */
    public List<String> promptCalls() {
        return List.copyOf(promptCalls);
    }

    /** The window ids that the client's {@code Prompt} calls gave, in call order. */
    public List<String> promptWindowIds() {
        return List.copyOf(promptWindowIds);
    }

    /** The paths of the prompts that the client called {@code Dismiss} on, in call order. */
    public List<String> dismissCalls() {
        return List.copyOf(dismissCalls);
    }

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

    /** The secret's value as the last {@code GetSecret} sent it: encrypted, as it crossed the bus. */
    public byte[] lastCiphertext() {
        byte[] ct = lastCiphertext;
        return ct == null ? null : ct.clone();
    }

    private volatile byte[] lastCiphertext;

    public boolean isItemLocked() {
        return itemLocked;
    }

    /** Whether the store holds an item at {@code path}. */
    public boolean hasItem(String path) {
        return (ITEM_PATH.equals(path) && !itemDeleted) || (SECOND_ITEM_PATH.equals(path) && secondItemLocked != null);
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

    /** The content types of the secrets that {@code CreateItem} and {@code SetSecret} were given, in call order. */
    public List<String> sentContentTypes() {
        return List.copyOf(sentContentTypes);
    }

    private final List<String> sentContentTypes = Collections.synchronizedList(new ArrayList<>());

    /**
     * Points the {@code default} alias at {@code path}, as a provider names its default collection.
     * Without it, {@code ReadAlias} answers "/", for no such collection.
     */
    public void setDefaultAlias(String path) { this.defaultAlias = path; }
    private volatile String defaultAlias;

    /** Makes {@code ReadAlias} answer with an error, as for an alias that the client cannot read. */
    public void setRefuseReadAlias(boolean refuse) { this.refuseReadAlias = refuse; }
    private volatile boolean refuseReadAlias;

    /** The attributes that the first item shows; it has none unless a test gives it some. */
    public void setItemAttributes(Map<String, String> attributes) { this.itemAttributes = Map.copyOf(attributes); }
    private volatile Map<String, String> itemAttributes = Map.of();

    /** Whether the item shows gnome-keyring's hashes for its label and attributes. */
    private boolean hashesItsMetadata(String path) {
        return isLocked(path) && reproduces(ProviderBug.GNOME_KEYRING_HASHES_THE_METADATA_OF_A_LOCKED_KEYRING);
    }

    /** {@code attributes} as gnome-keyring shows them for a locked keyring: hashed, but xdg:schema. */
    private static Map<String, String> hashed(Map<String, String> attributes) {
        Map<String, String> hashed = new HashMap<>();
        try {
            for (Map.Entry<String, String> attribute : attributes.entrySet()) {
                if ("xdg:schema".equals(attribute.getKey())) {
                    hashed.put(attribute.getKey(), attribute.getValue());
                    continue;
                }
                byte[] digest = java.security.MessageDigest.getInstance("MD5")
                        .digest(attribute.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                hashed.put("gkr:compat:hashed:" + attribute.getKey(), java.util.HexFormat.of().formatHex(digest));
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        return hashed;
    }

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

    /** How often {@code GetSecret} was called for a locked item. */
    public int lockedItemReads() {
        return lockedItemReads.get();
    }

    private final java.util.concurrent.atomic.AtomicInteger lockedItemReads = new java.util.concurrent.atomic.AtomicInteger();

    /**
     * Gives the next {@code count} sessions a shared secret whose top byte is zero, and every other
     * session one whose top byte is not, so that a test knows how many sessions the library opens:
     * it replaces a session of the first kind.
     */
    public void setZeroTopByteSecrets(int count) { this.zeroTopByteSecrets = count; }
    private volatile int zeroTopByteSecrets;

    /** How often {@code OpenSession} was called. */
    public int openSessionCalls() {
        return openSessionCalls.get();
    }

    private final java.util.concurrent.atomic.AtomicInteger openSessionCalls = new java.util.concurrent.atomic.AtomicInteger();

    /** How often {@code Close} was called on a session. */
    public int closeSessionCalls() {
        return closeSessionCalls.get();
    }

    private final java.util.concurrent.atomic.AtomicInteger closeSessionCalls = new java.util.concurrent.atomic.AtomicInteger();

    /** How often {@code Delete} was called on the collection. */
    public int collectionDeleteCalls() {
        return collectionDeleteCalls.get();
    }

    private final java.util.concurrent.atomic.AtomicInteger collectionDeleteCalls = new java.util.concurrent.atomic.AtomicInteger();

    private final java.util.concurrent.atomic.AtomicInteger setSecretCalls = new java.util.concurrent.atomic.AtomicInteger();

    private static boolean isItem(String path) {
        return ITEM_PATH.equals(path) || SECOND_ITEM_PATH.equals(path);
    }

    private void unlockItem(String path) {
        if (ITEM_PATH.equals(path)) itemLocked = false;
        if (SECOND_ITEM_PATH.equals(path) && secondItemLocked != null) secondItemLocked = false;
    }

    /** The collection's items: the first, and the second once it is added. */
    private List<DBusPath> items() {
        List<DBusPath> items = new ArrayList<>(List.of(new DBusPath(ITEM_PATH)));
        if (secondItemLocked != null) items.add(new DBusPath(SECOND_ITEM_PATH));
        return items;
    }

    /** Whether the item at {@code path} is locked, on its own or with its collection. */
    private boolean isLocked(String path) {
        boolean own = SECOND_ITEM_PATH.equals(path) ? Boolean.TRUE.equals(secondItemLocked) : itemLocked;
        return own || collectionLocked;
    }

    public void export() throws Exception {
        connection.exportObject(SERVICE_PATH, new ServiceImpl());
        connection.exportObject(COLLECTION_PATH, new CollectionImpl());
        connection.exportObject(ITEM_PATH, new ItemImpl(ITEM_PATH));
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
            alive();
            openSessionCalls.incrementAndGet();
            byte[] clientY = Static.Utils.toByteArray(input.getValue());
            if (clientY.length < 128 && reproduces(ProviderBug.KWALLET_REFUSES_A_SHORT_PUBLIC_KEY)) {
                throw new org.freedesktop.dbus.exceptions.DBusExecutionException(
                        "fake: a public key of " + clientY.length + " bytes");
            }
            try {
                DHParameterSpec params = new DHParameterSpec(SECOND_OAKLEY_GROUP_PRIME, BigInteger.valueOf(2), 1024);

                KeyPairGenerator gen = KeyPairGenerator.getInstance("DiffieHellman");
                gen.initialize(params);

                // As two's complement, the way QCA's BigInteger reads it, when KWallet's bug is on.
                BigInteger theirY = reproduces(ProviderBug.KWALLET_READS_THE_PUBLIC_KEY_AS_SIGNED)
                        ? new BigInteger(clientY) : new BigInteger(1, clientY);

                boolean zeroTopByte = zeroTopByteSecrets > 0;
                if (zeroTopByte) zeroTopByteSecrets--;
                KeyPair ours = gen.generateKeyPair();
                BigInteger p = params.getP();
                BigInteger ourY = ((DHPublicKey) ours.getPublic()).getY();
                BigInteger secret = theirY.modPow(((DHPrivateKey) ours.getPrivate()).getX(), p);
                // Until the shared secret's top byte is zero or not, as the session should have it:
                // 256 tries on average for a zero one. Each try adds one to the private exponent,
                // which takes a multiplication on each side. Drawing a new key pair takes two
                // exponentiations, and on a busy machine the draws outlasted the client's
                // two-second wait for the reply.
                while ((secret.bitLength() <= 1016) != zeroTopByte) {
                    ourY = ourY.multiply(params.getG()).mod(p);
                    secret = secret.multiply(theirY).mod(p);
                }
                byte[] shared = toPrimeLength(secret);
                sessionKey = hkdfSha256To128(
                        reproduces(ProviderBug.KWALLET_HASHES_THE_SHARED_SECRET_WITHOUT_LEADING_ZEROS)
                                ? withoutLeadingZeros(shared) : shared);

                return new Pair<>(new Variant<>(ourY.toByteArray()), new DBusPath(SESSION_PATH));
            } catch (Exception e) {
                throw new IllegalStateException("fake OpenSession failed", e);
            }
        }

        @Override
        public Pair<List<DBusPath>, DBusPath> Unlock(List<DBusPath> objects) {
            alive();
            for (DBusPath p : objects) unlockCalls.add(p.getPath());
            unlockRequests.add(objects.stream().map(DBusPath::getPath).toList());
            // The bug this fixture exists for: unlocking the COLLECTION does nothing to the item.
            List<String> items = objects.stream().map(DBusPath::getPath).filter(FakeSecretService::isItem).toList();
            boolean itemRequested = !items.isEmpty();
            if (!itemRequested) {
                if (refuseCollectionUnlock) {
                    return new Pair<>(new ArrayList<DBusPath>(), new DBusPath("/"));
                }
                if (requirePromptForCollectionUnlock && collectionLocked) {
                    // Unlocked only when a test answers the prompt's dialog, which shows once the
                    // client calls Prompt on it.
                    return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(newPrompt(true).path));
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
                itemUnlockPrompts.incrementAndGet();
                FakePrompt prompt = newPrompt(false);
                emitCompletedLater(prompt, true);
                return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(prompt.path));
            }
            if (unlockFirstItemWithoutPrompt && items.size() > 1) {
                // The first at once, the rest when the prompt is answered.
                unlockItem(items.get(0));
                List<String> rest = items.subList(1, items.size());
                itemUnlockPrompts.incrementAndGet();
                FakePrompt prompt = newPrompt(false);
                emitCompletedLater(prompt, false, () -> rest.forEach(FakeSecretService.this::unlockItem));
                return new Pair<>(new ArrayList<>(List.of(new DBusPath(items.get(0)))), new DBusPath(prompt.path));
            }
            if (requirePromptForItemOps) {
                // Unlocked only when the prompt is answered -- see emitCompletedLater. Doing it
                // here would mean a client that declines to prompt still sees the item unlocked.
                // One prompt for every item of the call, as KeePassXC shows one dialog for them.
                itemUnlockPrompts.incrementAndGet();
                FakePrompt prompt = newPrompt(false);
                emitCompletedLater(prompt, false, () -> items.forEach(FakeSecretService.this::unlockItem));
                return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(prompt.path));
            }
            items.forEach(FakeSecretService.this::unlockItem);
            return new Pair<>(new ArrayList<>(objects), new DBusPath("/"));
        }

        @Override
        public Pair<List<DBusPath>, DBusPath> Lock(List<DBusPath> objects) {
            alive();
            for (DBusPath p : objects) lockCalls.add(p.getPath());
            boolean collectionLockRequested = objects.stream().anyMatch(p -> COLLECTION_PATH.equals(p.getPath()));
            if (collectionLockRequested && collectionLocked
                    && reproduces(ProviderBug.KWALLET_REFUSES_TO_LOCK_A_LOCKED_WALLET)) {
                throw new org.freedesktop.dbus.exceptions.DBusExecutionException("fake: the wallet is closed already");
            }
            boolean itemRequested = objects.stream().anyMatch(p -> ITEM_PATH.equals(p.getPath()));
            if (itemRequested && requirePromptForItemOps && !itemLocked) {
                // Only the item goes behind a prompt, and only when it is not already locked;
                // every other case falls through, as in Unlock. Nothing is scheduled: the item is
                // locked only when a test calls approvePendingPrompt(), so a client that declines
                // to prompt leaves it unlocked, as a real provider does when Prompt() is never
                // called.
                FakePrompt prompt = awaitApproval(() -> itemLocked = true, null);
                return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(prompt.path));
            }
            boolean collectionRequested = objects.stream().anyMatch(p -> COLLECTION_PATH.equals(p.getPath()));
            if (collectionRequested && requirePromptForCollectionLock && !collectionLocked) {
                // As for the item above: locked only when a test answers the prompt.
                FakePrompt prompt = awaitApproval(() -> collectionLocked = true, null);
                return new Pair<>(new ArrayList<DBusPath>(), new DBusPath(prompt.path));
            }
            for (DBusPath p : objects) {
                if (ITEM_PATH.equals(p.getPath())) itemLocked = true;
                if (COLLECTION_PATH.equals(p.getPath())) collectionLocked = true;
            }
            return new Pair<>(new ArrayList<>(objects), new DBusPath("/"));
        }

        @Override
        public Pair<List<DBusPath>, List<DBusPath>> SearchItems(Map<String, String> attributes) {
            alive();
            if (!searchReplyDelay.isZero()) {
                try {
                    Thread.sleep(searchReplyDelay.toMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (findsNothing(attributes)) return new Pair<>(new ArrayList<>(), new ArrayList<>());
            // (unlocked, locked). Reporting the item in neither list when it is locked would be a
            // trap for the next test to use this: it would look like the item does not exist.
            // Same condition as the Locked property and GetSecret below: a fixture that reports an
            // item locked in one place and hands out its plaintext in another teaches the next test
            // something no real provider does.
            List<DBusPath> unlocked = new ArrayList<>();
            List<DBusPath> locked = new ArrayList<>();
            for (DBusPath item : items()) (isLocked(item.getPath()) ? locked : unlocked).add(item);
            return new Pair<>(unlocked, locked);
        }

        @Override
        public Pair<DBusPath, DBusPath> CreateCollection(Map<String, Variant<?>> properties, String alias) {
            alive();
            Variant<?> label = properties.get(Collection.LABEL);
            createCollectionCalls.add(label == null ? "" : String.valueOf(label.getValue()));
            // Through a prompt, as a provider without gnome-keyring's password interface creates a
            // collection: the user sets the password there. The user cancels it here, so nothing is
            // created; the tests need to see that the request was made, not a new collection.
            FakePrompt prompt = newPrompt(false);
            emitCompletedLater(prompt, true);
            return new Pair<>(new DBusPath("/"), new DBusPath(prompt.path));
        }

        @Override
        public DBusPath ReadAlias(String name) {
            alive();
            if (refuseReadAlias) throw new org.freedesktop.dbus.exceptions.DBusExecutionException("fake: ReadAlias refused");
            String target = "default".equals(name) ? defaultAlias : null;
            return new DBusPath(target == null ? "/" : target);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            alive();
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
            alive();
            return findsNothing(attributes) ? new ArrayList<>() : items();
        }

        @Override
        public Pair<DBusPath, DBusPath> CreateItem(Map<String, Variant<?>> properties, WireSecret secret, boolean replace) {
            alive();
            Variant<?> label = properties.get(Item.LABEL);
            createItemCalls.add(label == null ? "" : String.valueOf(label.getValue()));
            createItemPropertyNames.add(java.util.Set.copyOf(properties.keySet()));
            sentContentTypes.add(secret.contentType());
            if (!properties.containsKey(Item.ATTRIBUTES)
                    && reproduces(ProviderBug.OO7_PANICS_ON_CREATE_ITEM_WITHOUT_ATTRIBUTES)) {
                neverAnswer();
            }
            checkContentType(secret.contentType());
            // Through a prompt, as KeePassXC creates every item. The fake stores nothing: answering
            // the prompt reports CREATED_ITEM_PATH in its result, where KeePassXC reports the item.
            FakePrompt prompt = awaitApproval(() -> { }, new Variant<>(new DBusPath(CREATED_ITEM_PATH), "o"));
            return new Pair<>(new DBusPath("/"), new DBusPath(prompt.path));
        }

        @Override
        public DBusPath Delete() {
            alive();
            // Counted, not carried out: the collection and its item stay for the rest of the test.
            collectionDeleteCalls.incrementAndGet();
            return new DBusPath("/");
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            alive();
            switch (property) {
                case "Locked":  return (A) Boolean.valueOf(collectionLocked);
                case "Items":   return (A) new Variant<>(itemsHidden() ? new ArrayList<DBusPath>() : items(), "ao");
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
        private final String path;

        ItemImpl(String path) {
            this.path = path;
        }

        /** Fails the call when the item is not on the bus, as an unknown object does. */
        private void reachable() {
            alive();
            if (itemsHidden()) throw new org.freedesktop.dbus.errors.UnknownObject("fake: no such object " + path);
        }

        @Override
        public DBusPath Delete() {
            reachable();
            if (isLocked(path)) {
                // "Done", and the item kept, as KWallet keeps its secret.
                if (reproduces(ProviderBug.KWALLET_ANSWERS_DELETE_OF_A_LOCKED_ITEM_AS_DONE)) return new DBusPath("/");
                throw new org.freedesktop.Secret.Error.IsLocked("fake: the item is locked");
            }
            // Deleted at once, answering "/" for "no prompt necessary", as gnome-keyring does. The
            // fake does not own org.gnome.keyring, so the client sees a provider other than
            // gnome-keyring giving that answer. oo7 deletes every item that has the deleted one's
            // attributes: every item here, as the fake's items have none.
            List<String> deleted = reproduces(ProviderBug.OO7_DELETE_REMOVES_EVERY_ITEM_WITH_THE_ATTRIBUTES)
                    ? items().stream().map(DBusPath::getPath).filter(FakeSecretService.this::hasItem).toList()
                    : List.of(path);
            for (String gone : deleted) {
                if (ITEM_PATH.equals(gone)) itemDeleted = true;
                else secondItemLocked = null;
                connection.unExportObject(gone);
            }
            return new DBusPath("/");
        }

        @Override
        public WireSecret GetSecret(DBusPath session) {
            reachable();
            boolean locked = isLocked(path);
            if (locked) {
                lockedItemReads.incrementAndGet();
                // What a provider does for a locked item -- including one locked only because its
                // collection is. The client must not get here.
                if (!reproduces(ProviderBug.KWALLET_READS_A_LOCKED_ITEM_AS_EMPTY)) {
                    throw new org.freedesktop.Secret.Error.IsLocked("fake: the item is locked");
                }
            }
            try {
                byte[] iv = new byte[16];
                new SecureRandom().nextBytes(iv);
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), new IvParameterSpec(iv));
                String value = ITEM_PATH.equals(path) ? secretValue : SECOND_SECRET_VALUE;
                byte[] ct = c.doFinal(locked ? new byte[0] : value.getBytes(secretEncoding));
                lastCiphertext = ct.clone();
                return new WireSecret(new DBusPath(SESSION_PATH), iv, ct, reportedContentType());
            } catch (Exception e) {
                throw new IllegalStateException("fake GetSecret failed", e);
            }
        }

        /** The stored content type as the provider gives it back. */
        private String reportedContentType() {
            if (reproduces(ProviderBug.GNOME_KEYRING_GIVES_EVERY_SECRET_AS_TEXT_PLAIN)) return "text/plain";
            boolean textPlain = secretContentType.split(";", 2)[0].trim().equalsIgnoreCase("text/plain");
            if (textPlain && reproduces(ProviderBug.KEEPASSXC_DROPS_THE_CHARSET)) return "text/plain";
            return secretContentType;
        }

        @Override
        @SuppressWarnings("unchecked")
        public <A> A Get(String iface, String property) {
            reachable();
            switch (property) {
                // gnome-keyring reports an item as locked whenever its collection is locked, so
                // the fake does too when asked to. This is what makes the regression reproducible.
                case "Locked":     return (A) Boolean.valueOf(isLocked(path));
                case "Attributes": {
                    Map<String, String> shown = ITEM_PATH.equals(path) ? itemAttributes : Map.of();
                    if (hashesItsMetadata(path)) shown = hashed(shown);
                    return (A) new Variant<>(new HashMap<>(shown), "a{ss}");
                }
                case "Label":
                    if (hashesItsMetadata(path)) return (A) "";
                    return (A) (ITEM_PATH.equals(path) ? "fake-item" : "fake-item-2");
                default: throw new IllegalArgumentException("fake: unsupported property " + property);
            }
        }

        @Override
        public void SetSecret(WireSecret secret) {
            reachable();
            setSecretCalls.incrementAndGet();
            sentContentTypes.add(secret.contentType());
            checkContentType(secret.contentType());
            // Stores nothing either way: KWallet answers success and drops it.
            if (isLocked(path) && !reproduces(ProviderBug.KWALLET_DROPS_THE_SECRET_FOR_A_LOCKED_ITEM)) {
                throw new org.freedesktop.Secret.Error.IsLocked("fake: the item is locked");
            }
        }

        @Override
        public <A> void Set(String iface, String property, A value) {
            reachable();
            // Changes nothing: the tests need to see which properties were set, not the new values.
            if (refuseItemPropertyChanges) throw new IllegalStateException("fake: the item is locked");
            if (isLocked(path) && !takesChangesWhileLocked()) {
                throw new org.freedesktop.Secret.Error.IsLocked("fake: the item is locked");
            }
            itemPropertySets.add(property);
        }

        /**
         * KWallet takes a change to an item of a closed wallet, and KeePassXC one to an item that it
         * keeps locked for the client while the database is open.
         */
        private boolean takesChangesWhileLocked() {
            return collectionLocked
                    ? reproduces(ProviderBug.KWALLET_TAKES_THE_LABEL_OF_A_LOCKED_ITEM)
                    : reproduces(ProviderBug.KEEPASSXC_CHANGES_AN_ITEM_IT_HAS_NOT_ALLOWED);
        }

        @Override public Map<String, Variant<?>> GetAll(String iface) { return Map.of(); }
        @Override public String getObjectPath() { return path; }
        @Override public boolean isRemote() { return false; }
    }

    private final class SessionImpl implements WireSession {
        @Override public void Close() { alive(); closeSessionCalls.incrementAndGet(); }
        @Override public String getObjectPath() { return SESSION_PATH; }
        @Override public boolean isRemote() { return false; }
    }


    // ---- prompts ---------------------------------------------------------------------------

    /**
     * A prompt that the fake handed out. As on a provider, each has a path of its own and is an
     * object on the bus. Its fields are guarded by {@link #promptLock}.
     */
    private static final class FakePrompt {
        final String path;
        /** Unlocks the collection through gnome-keyring's dialog, shown one at a time. */
        final boolean unlocksCollection;
        boolean prompted;
        boolean completed;

        FakePrompt(String path, boolean unlocksCollection) {
            this.path = path;
            this.unlocksCollection = unlocksCollection;
        }
    }

    private final Object promptLock = new Object();
    private int promptNumber;
    /**
     * The unlock prompts that the client has called Prompt on and that have no answer, in that
     * order: the first one's dialog is on the screen, and the others wait for it, as gnome-keyring
     * queues them.
     */
    private final Deque<FakePrompt> unlockDialogs = new ArrayDeque<>();
    /**
     * A dismissed unlock prompt whose dialog is still on the screen, as gnome-keyring 51 leaves it
     * ({@link ProviderBug#GNOME_KEYRING_STRANDS_THE_UNLOCKS_BEHIND_A_DISMISSED_DIALOG}). The
     * prompts that wait do not move while it is up.
     */
    private FakePrompt dismissedDialog;
    /** Set when no unlock prompt that waits will ever be resumed, for the same bug. */
    private boolean unlocksStuck;
    private final List<String> promptCalls = Collections.synchronizedList(new ArrayList<>());
    private final List<String> promptWindowIds = Collections.synchronizedList(new ArrayList<>());
    private final List<String> dismissCalls = Collections.synchronizedList(new ArrayList<>());

    /** Hands out a new prompt, on the bus. */
    private FakePrompt newPrompt(boolean unlocksCollection) {
        FakePrompt prompt;
        synchronized (promptLock) {
            prompt = new FakePrompt(PROMPT_PREFIX + (unlocksCollection ? "u" : "p") + ++promptNumber,
                    unlocksCollection);
        }
        try {
            connection.exportObject(prompt.path, new PromptImpl(prompt));
        } catch (DBusException e) {
            throw new IllegalStateException("fake: could not export a prompt", e);
        }
        return prompt;
    }

    private final class PromptImpl implements WirePrompt {
        private final FakePrompt prompt;

        PromptImpl(FakePrompt prompt) {
            this.prompt = prompt;
        }

        @Override
        public void Prompt(String windowId) {
            alive();
            promptCalls.add(prompt.path);
            promptWindowIds.add(windowId);
            synchronized (promptLock) {
                if (prompt.prompted || prompt.completed) return;
                prompt.prompted = true;
                // Every other prompt is answered by a timer or by the test, as the call that
                // handed it out arranged.
                if (!prompt.unlocksCollection) return;
                unlockDialogs.addLast(prompt);
                showNextDialog();
            }
        }

        @Override
        public void Dismiss() {
            alive();
            dismissCalls.add(prompt.path);
            synchronized (promptLock) {
                if (prompt.completed) return;
                FakePrompt inProgress = unlockInProgress();
                if (prompt.unlocksCollection && inProgress != null) {
                    if (inProgress == prompt
                            ? reproduces(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_UNLOCK_DIALOG)
                            : reproduces(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK)) {
                        aborted = true;
                        throw new org.freedesktop.dbus.errors.NoReply(
                                "fake: perform_next_unlock: assertion failed: (!self->current)");
                    }
                    if (inProgress == prompt
                            && reproduces(ProviderBug.GNOME_KEYRING_STRANDS_THE_UNLOCKS_BEHIND_A_DISMISSED_DIALOG)) {
                        unlockDialogs.removeFirst();
                        complete(prompt, true, noResult());
                        dismissedDialog = prompt;
                        return;
                    }
                }
                boolean shown = inProgress == prompt;
                unlockDialogs.remove(prompt);
                if (pendingPrompt == prompt) clearPendingApproval();
                if (reproduces(ProviderBug.OO7_DISMISS_SENDS_NO_COMPLETED)) {
                    // Gone, without a word.
                    prompt.completed = true;
                    connection.unExportObject(prompt.path);
                } else {
                    complete(prompt, true, noResult());
                }
                if (shown) showNextDialog();
            }
        }

        @Override public String getObjectPath() { return prompt.path; }
        @Override public boolean isRemote() { return false; }
    }

    /**
     * Completes the waiting unlock prompts from the first while the collection is unlocked:
     * gnome-keyring shows one unlock dialog at a time, and a prompt whose collection was unlocked
     * while it waited completes without one. The first that remains shows its dialog. The caller
     * holds {@link #promptLock}.
     */
    private void showNextDialog() {
        FakePrompt next;
        while ((next = unlockInProgress()) != null && !collectionLocked) {
            unlockDialogs.removeFirst();
            complete(next, false, unlockedCollection());
        }
    }

    /**
     * The unlock prompt in progress: the first one that waits, whose dialog is on the screen. None
     * while the dialog of a dismissed prompt is up, or when the waiting ones are stuck. The caller
     * holds {@link #promptLock}.
     */
    private FakePrompt unlockInProgress() {
        return dismissedDialog == null && !unlocksStuck ? unlockDialogs.peekFirst() : null;
    }

    /**
     * Answers the dialog that gnome-keyring 51 leaves up for a dismissed unlock prompt, if there is
     * one. The answer unlocks the collection when the user gives the password, and the dismissed
     * prompt's call, completing then, takes the first waiting prompt off the queue in its own
     * place, never to resume it. Any prompt that waits behind that one waits for good. The caller
     * holds {@link #promptLock}.
     *
     * @return whether there was such a dialog
     */
    private boolean answerDismissedDialog(boolean approved) {
        if (dismissedDialog == null) return false;
        dismissedDialog = null;
        if (approved) collectionLocked = false;
        unlockDialogs.pollFirst();
        unlocksStuck = !unlockDialogs.isEmpty();
        return true;
    }

    /** Ends {@code prompt} and announces how. The caller holds {@link #promptLock}. */
    private void complete(FakePrompt prompt, boolean dismissed, Variant<?> result) {
        prompt.completed = true;
        try {
            connection.sendMessage(new de.swiesend.secretservice.interfaces.Prompt.Completed(
                    prompt.path, dismissed, result));
        } catch (Exception e) {
            // The test may already have torn the bus down; a Completed nobody is waiting for is
            // not a failure. Throwing here printed stack traces on a passing build, which the
            // next person to read CI output takes for an error.
            log("fake: dropped a Completed signal after teardown: " + e.getClass().getName());
        }
    }

    private static Variant<?> noResult() {
        return new Variant<>(new ArrayList<DBusPath>(), "ao");
    }

    private static Variant<?> unlockedCollection() {
        return new Variant<>(new ArrayList<>(List.of(new DBusPath(COLLECTION_PATH))), "ao");
    }

    /**
     * Completes {@code prompt} shortly after the call that handed it out returns, as a provider does
     * once the user has answered. The delay lets the client arm its signal handler first -- it does
     * that inside Prompt.await, which it only reaches after Unlock has returned. A prompt that the
     * client dismissed meanwhile has had its answer.
     */
    private void emitCompletedLater(FakePrompt prompt, boolean dismissed) {
        emitCompletedLater(prompt, dismissed, () -> { });
    }

    /** @param onAnswered applied when the prompt is answered, before the signal goes out. */
    private void emitCompletedLater(FakePrompt prompt, boolean dismissed, Runnable onAnswered) {
        emitCompletedLater(prompt, dismissed, onAnswered, noResult());
    }

    /** @param result the prompt's result, which depends on the operation that asked for it */
    private void emitCompletedLater(FakePrompt prompt, boolean dismissed, Runnable onAnswered, Variant<?> result) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(150);
                synchronized (promptLock) {
                    if (prompt.completed) return;
                    if (!dismissed) onAnswered.run();
                    complete(prompt, dismissed, result);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "fake-prompt");
        t.setDaemon(true);
        promptThread = t;
        t.start();
    }

    /** {@code value} in the prime's 128 bytes, big-endian, as KeyAgreement gives a shared secret. */
    private static byte[] toPrimeLength(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] bytes = new byte[128];
        int length = Math.min(raw.length, bytes.length);
        java.lang.System.arraycopy(raw, raw.length - length, bytes, bytes.length - length, length);
        return bytes;
    }

    /** {@code bytes} without their leading zero bytes. */
    private static byte[] withoutLeadingZeros(byte[] bytes) {
        int start = 0;
        while (start < bytes.length - 1 && bytes[start] == 0) start++;
        return java.util.Arrays.copyOfRange(bytes, start, bytes.length);
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
