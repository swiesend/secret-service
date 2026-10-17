package de.swiesend.secretservice;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.handlers.MessageHandler;
import de.swiesend.secretservice.handlers.Messaging;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class Service extends Messaging implements de.swiesend.secretservice.interfaces.Service {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(
            CollectionCreated.class, CollectionChanged.class, CollectionDeleted.class);
    private static final Logger log = LoggerFactory.getLogger(Service.class);

    // Volatile: a prompt reads it on the thread that shows it.
    private volatile String windowHandle = "";

    public Service(DBusConnection connection) {
        super(connection, signals,
                Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS,
                Static.Interfaces.SERVICE);
    }

    /** The window that the prompts of this service are shown over; see {@link #setWindowHandle}. */
    public String getWindowHandle() {
        return windowHandle;
    }

    /**
     * Sets the window that the prompts of this service are shown over: the provider places its
     * dialog on it. The handle is the {@code window_id} of {@code Prompt.Prompt}, empty by default,
     * for no window. Its form is the provider's: KeePassXC reads the number of an X11 window, in
     * decimal or after {@code 0x} in hex; oo7 reads a window identifier of the desktop portals,
     * {@code x11:} and an X11 window's number in hex, or {@code wayland:} and a handle exported
     * with xdg-foreign. Both show the dialog on no window when they cannot read the handle.
     *
     * @param handle the window handle, or {@code ""} for none
     * @throws NullPointerException if {@code handle} is null
     */
    public void setWindowHandle(String handle) {
        this.windowHandle = Objects.requireNonNull(handle, "handle must not be null");
    }

    @Override
    public Optional<Pair<Variant<byte[]>, DBusPath>> openSession(String algorithm, Variant input) {
        return openSessionChecked(algorithm, input).value();
    }

    /**
     * As {@link #openSession(String, Variant)}, but answering why no session opened.
     *
     * @since 4.0.0
     */
    public Result<Pair<Variant<byte[]>, DBusPath>> openSessionChecked(String algorithm, Variant input) {
        MessageHandler.Reply reply = sendChecked("OpenSession", "sv", algorithm, input);
        if (reply.outcome() != MessageHandler.Outcome.OK) {
            return Result.failed(Failure.from(reply, "The provider opened no session"));
        }
        return reply.value()
                .filter(response -> !Static.Utils.isNullOrEmpty(response) && response.length == 2)
                .map(response -> new Pair<>((Variant<byte[]>) response[0], (DBusPath) response[1]))
                .map(pair -> {
                    log.debug("Got session: " + pair.b.getPath());
                    return Result.ok(pair);
                })
                .orElseGet(() -> Result.failed(Failure.Reason.OTHER, "The provider answered OpenSession without a session"));
    }

    @Override
    public Optional<Pair<DBusPath, DBusPath>> createCollection(Map<String, Variant> properties, String alias) {
        return createCollectionChecked(properties, alias).value();
    }

    /**
     * As {@link #createCollection(Map, String)}, but answering why the call failed.
     *
     * @since 4.0.0
     */
    public Result<Pair<DBusPath, DBusPath>> createCollectionChecked(Map<String, Variant> properties, String alias) {
        String a = alias == null ? "" : alias;
        MessageHandler.Reply reply = sendChecked("CreateCollection", "a{sv}s", properties, a);
        if (reply.outcome() != MessageHandler.Outcome.OK) {
            return Result.failed(Failure.from(reply, "The provider created no collection"));
        }
        return reply.value()
                .filter(response -> !Static.Utils.isNullOrEmpty(response) && response.length == 2)
                .map(response -> Result.ok(
                        new Pair<DBusPath, DBusPath>((DBusPath) response[0], (DBusPath) response[1])))
                .orElseGet(() -> Result.failed(Failure.Reason.OTHER,
                        "The provider answered CreateCollection without its two results"));
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
        return unlockChecked(objects).value();
    }

    /**
     * As {@link #unlock(List)}, but answering why the call failed.
     *
     * @since 4.0.0
     */
    public Result<Pair<List<DBusPath>, DBusPath>> unlockChecked(List<DBusPath> objects) {
        MessageHandler.Reply reply = sendChecked("Unlock", "ao", objects);
        if (reply.outcome() != MessageHandler.Outcome.OK) {
            return Result.failed(Failure.from(reply, "The provider did not unlock " + objects));
        }
        return reply.value()
                .filter(response -> !Static.Utils.isNullOrEmpty(response) && response.length == 2)
                .map(response -> Result.ok(
                        new Pair<List<DBusPath>, DBusPath>((List<DBusPath>) response[0], (DBusPath) response[1])))
                .orElseGet(() -> Result.failed(Failure.Reason.OTHER, "The provider answered Unlock without its two results"));
    }

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

    @Override
    public Optional<DBusPath> changeLock(DBusPath collection) {
        return send("ChangeLock", "o", collection).flatMap(response ->
                Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((DBusPath) response[0]));
    }

    @Override
    public Optional<Map<DBusPath, Secret>> getSecrets(List<DBusPath> items, DBusPath session) {
        return send("GetSecrets", "aoo", items, session).flatMap(response ->
                Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((Map<DBusPath, Secret>) response[0]));
    }

    @Override
    public Optional<DBusPath> readAlias(String name) {
        return readAliasChecked(name).value();
    }

    /**
     * As {@link #readAlias(String)}, but answering why the alias could not be read. A provider that
     * knows no such alias answers {@code "/"}, and that is a success.
     *
     * @since 4.0.0
     */
    public Result<DBusPath> readAliasChecked(String name) {
        MessageHandler.Reply reply = sendChecked("ReadAlias", "s", name);
        if (reply.outcome() != MessageHandler.Outcome.OK) {
            return Result.failed(Failure.from(reply, "The provider did not read the alias " + name));
        }
        return reply.value()
                .filter(response -> !Static.Utils.isNullOrEmpty(response) && response[0] instanceof DBusPath)
                .map(response -> Result.ok((DBusPath) response[0]))
                .orElseGet(() -> Result.failed(Failure.Reason.OTHER, "The provider answered ReadAlias without a path"));
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
