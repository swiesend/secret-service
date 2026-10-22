package de.swiesend.secretservice;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.handlers.Messaging;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class Service extends Messaging implements de.swiesend.secretservice.interfaces.Service {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(
            CollectionCreated.class, CollectionChanged.class, CollectionDeleted.class);
    private static final Logger log = LoggerFactory.getLogger(Service.class);

    public Service(DBusConnection connection) {
        super(connection, signals,
                Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS,
                Static.Interfaces.SERVICE);
    }

    @Override
    public Optional<Pair<Variant<byte[]>, DBusPath>> openSession(String algorithm, Variant input) {
        return send("OpenSession", "sv", algorithm, input)
                .filter(response -> !Static.Utils.isNullOrEmpty(response) && response.length == 2)
                .flatMap(response -> Optional.of(new Pair<>(asBytes((Variant<?>) response[0]), (DBusPath) response[1])))
                .map(pair -> {
                    log.debug("Got session: " + pair.b.getPath());
                    return pair;
                });
    }

    @Override
    public Optional<Pair<DBusPath, DBusPath>> createCollection(Map<String, Variant> properties, String alias) {
        String a = alias == null ? "" : alias;
        return send("CreateCollection", "a{sv}s", properties, a).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<DBusPath, DBusPath>((DBusPath) response[0], (DBusPath) response[1])));
    }

    @Override
    public Optional<Pair<DBusPath, DBusPath>> createCollection(Map<String, Variant> properties) {
        return createCollection(properties, "");
    }

    @Override
    public Optional<Pair<List<DBusPath>, List<DBusPath>>> searchItems(Map<String, String> attributes) {
        return send("SearchItems", "a{ss}", attributes).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<List<DBusPath>, List<DBusPath>>((List<DBusPath>) response[0], (List<DBusPath>) response[1])));
    }

    @Override
    public Optional<Pair<List<DBusPath>, DBusPath>> unlock(List<DBusPath> objects) {
        Optional<Pair<List<DBusPath>, DBusPath>> unlocked = send("Unlock", "ao", objects).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<List<DBusPath>, DBusPath>((List<DBusPath>) response[0], (DBusPath) response[1])));
        // For Prompt.await, which leaves an unlock prompt of gnome-keyring open where it dismisses
        // any other prompt that nobody answers.
        unlocked.map(pair -> pair.b)
                .filter(prompt -> prompt.getPath() != null && !"/".equals(prompt.getPath()))
                .ifPresent(prompt -> unlockPrompts.add(prompt.getPath()));
        return unlocked;
    }

    /** The prompts that {@link #unlock} gave. */
    private final Set<String> unlockPrompts = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Whether {@code prompt} is one that {@link #unlock} gave. */
    boolean gaveUnlockPrompt(DBusPath prompt) {
        return unlockPrompts.contains(prompt.getPath());
    }

    /**
     * Whether gnome-keyring serves the secrets, as {@link ProviderDetector} tells. Asked once: the
     * provider that serves the secrets does not change while the session's objects live.
     */
    boolean isGnomeKeyring() {
        Boolean known = gnomeKeyring;
        if (known == null) {
            known = ProviderDetector.detectProvider(getConnection()) == ProviderDetector.Provider.GNOME_KEYRING;
            gnomeKeyring = known;
        }
        return known;
    }

    private volatile Boolean gnomeKeyring;

    @Override
    public Optional<Pair<List<DBusPath>, DBusPath>> lock(List<DBusPath> objects) {
        return send("Lock", "ao", objects).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<List<DBusPath>, DBusPath>((List<DBusPath>) response[0], (DBusPath) response[1])));
    }

    @Override
    public boolean lockService() {
        return send("LockService", "").isPresent();
    }

    /**
     * The output as declared: dbus-java can hand a byte array over as {@code List<Byte>}, which a
     * caller reading {@code byte[]} from it got as a ClassCastException. A plain session's output
     * is the empty string, and stays as it is.
     */
    @SuppressWarnings("unchecked")
    private static Variant<byte[]> asBytes(Variant<?> output) {
        if ("ay".equals(output.getSig()) && !(output.getValue() instanceof byte[])) {
            return new Variant<>(Static.Utils.toByteArray(output.getValue()), "ay");
        }
        return (Variant<byte[]>) output;
    }

    @Override
    public Optional<DBusPath> changeLock(DBusPath collection) {
        return send("ChangeLock", "o", collection).flatMap(response ->
                Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((DBusPath) response[0]));
    }

    @Override
    public Optional<Map<DBusPath, Secret>> getSecrets(List<DBusPath> items, DBusPath session) {
        return send("GetSecrets", "aoo", items, session).flatMap(response -> {
            if (Static.Utils.isNullOrEmpty(response)) return Optional.empty();
            // Decoded without type information, each (oayays) arrives as an Object[]. A cast of the
            // map let that through, and the first read of a value threw ClassCastException.
            try {
                Map<DBusPath, Secret> secrets = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) response[0]).entrySet()) {
                    Object value = entry.getValue();
                    secrets.put((DBusPath) entry.getKey(),
                            value instanceof Secret secret ? secret : Item.toSecret((Object[]) value));
                }
                return Optional.of(secrets);
            } catch (ClassCastException | IndexOutOfBoundsException | IllegalStateException e) {
                log.error("GetSecrets returned a reply of an unexpected shape.");
                return Optional.empty();
            }
        });
    }

    @Override
    public Optional<DBusPath> readAlias(String name) {
        return send("ReadAlias", "s", name).flatMap(response ->
                Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((DBusPath) response[0]));
    }

    @Override
    public boolean setAlias(String name, DBusPath collection) {
        return send("SetAlias", "so", name, collection).isPresent();
    }

    @Override
    public Optional<List<DBusPath>> getCollections() {
        return getProperty("Collections").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((List<DBusPath>) variant.getValue())
        );
    }

    @Override
    public boolean isRemote() {
        return false;
    }

    @Override
    public String getObjectPath() {
        return Static.ObjectPaths.SECRETS;
    }

}
