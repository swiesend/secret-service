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
 * <p>Only the members the read path touches are implemented. This is a test fixture, not a
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
    }

    @DBusInterfaceName(Static.Interfaces.COLLECTION)
    public interface WireCollection extends DBusInterface {
        List<DBusPath> SearchItems(Map<String, String> attributes);
    }

    @DBusInterfaceName(Static.Interfaces.ITEM)
    public interface WireItem extends DBusInterface {
        Secret GetSecret(DBusPath session);
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
                // A collection-level unlock succeeds immediately and, crucially, does NOT touch the
                // item. That asymmetry is the bug under test.
                collectionLocked = false;
                return new Pair<>(new ArrayList<>(objects), new DBusPath("/"));
            }
            if (dismissPrompts) {
                // A REAL prompt path, and a Completed(dismissed=true) to go with it. Answering "/"
                // instead would send the client down Prompt.await's getLastHandledSignal branch,
                // where no signal is ever handled -- so every test hit the "no prompt result" path
                // and the dismissal branch had no coverage at all.
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
                // Only the item goes behind a prompt, and only when it is not already locked. The
                // Unlock counterpart lets every other case fall through, and so must this: an
                // earlier version returned here for a Lock naming both paths, silently dropping
                // the collection and reporting an empty locked list as if the request had vanished.
                emitCompletedLater(false, () -> itemLocked = true);
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
        public Secret GetSecret(DBusPath session) {
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
                byte[] ct = c.doFinal(SECRET_VALUE.getBytes(StandardCharsets.UTF_8));
                return new Secret(new DBusPath(SESSION_PATH), iv, ct, "text/plain; charset=utf8");
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

        @Override public <A> void Set(String iface, String property, A value) { }
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
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(150);
                if (!dismissed) onAnswered.run();
                connection.sendMessage(new de.swiesend.secretservice.interfaces.Prompt.Completed(
                        PROMPT_PATH, dismissed, new Variant<>(new ArrayList<DBusPath>(), "ao")));
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
