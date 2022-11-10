package de.swiesend.secretservice;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.handlers.Messaging;

import java.util.*;

public class Service extends Messaging implements de.swiesend.secretservice.interfaces.Service {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(
            CollectionCreated.class, CollectionChanged.class, CollectionDeleted.class);
    private static final Logger log = LoggerFactory.getLogger(Service.class);
    private Session session = null;

    public Service(DBusConnection connection) {
        super(connection, signals,
                Static.Service.SECRETS,
                Static.ObjectPaths.SECRETS,
                Static.Interfaces.SERVICE);
    }

    @Override
    public Optional<Pair<Variant<byte[]>, ObjectPath>> openSession(String algorithm, Variant input) {
        return send("OpenSession", "sv", algorithm, input)
                .filter(response -> !Static.Utils.isNullOrEmpty(response) && response.length == 2)
                .flatMap(response -> Optional.of(new Pair<>((Variant<byte[]>) response[0], (ObjectPath) response[1])))
                .map(pair -> {
                    log.debug("Got session: " + pair.b.getPath());
                    session = new Session(pair.b, this);
                    return pair;
                });
    }

    @Override
    public Optional<Pair<ObjectPath, ObjectPath>> createCollection(Map<String, Variant> properties, String alias) {
        String a = alias == null ? "" : alias;
        return send("CreateCollection", "a{sv}s", properties, a).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<ObjectPath, ObjectPath>((ObjectPath) response[0], (ObjectPath) response[1])));
    }

    @Override
    public Optional<Pair<ObjectPath, ObjectPath>> createCollection(Map<String, Variant> properties) {
        return createCollection(properties, "");
    }

    @Override
    public Optional<Pair<List<ObjectPath>, List<ObjectPath>>> searchItems(Map<String, String> attributes) {
        return send("SearchItems", "a{ss}", attributes).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<List<ObjectPath>, List<ObjectPath>>((List<ObjectPath>) response[0], (List<ObjectPath>) response[1])));
    }

    @Override
    public Optional<Pair<List<ObjectPath>, ObjectPath>> unlock(List<ObjectPath> objects) {
        return send("Unlock", "ao", objects).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<List<ObjectPath>, ObjectPath>((List<ObjectPath>) response[0], (ObjectPath) response[1])));
    }

    @Override
    public Optional<Pair<List<ObjectPath>, ObjectPath>> lock(List<ObjectPath> objects) {
        return send("Lock", "ao", objects).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<List<ObjectPath>, ObjectPath>((List<ObjectPath>) response[0], (ObjectPath) response[1])));
    }

    @Override
    public boolean lockService() {
        return send("LockService", "").isPresent();
    }

    @Override
    public Optional<ObjectPath> changeLock(ObjectPath collection) {
        return send("ChangeLock", "o", collection).flatMap(response ->
                Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((ObjectPath) response[0]));
    }

    @Override
    public Optional<Map<ObjectPath, Secret>> getSecrets(List<ObjectPath> items, ObjectPath session) {
        return send("GetSecrets", "aoo", items, session).flatMap(response ->
                Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((Map<ObjectPath, Secret>) response[0]));
    }

    @Override
    public Optional<ObjectPath> readAlias(String name) {
        return send("ReadAlias", "s", name).flatMap(response ->
                Static.Utils.isNullOrEmpty(response) ? Optional.empty() : Optional.of((ObjectPath) response[0]));
    }

    @Override
    public boolean setAlias(String name, ObjectPath collection) {
        return send("SetAlias", "so", name, collection).isPresent();
    }

    @Override
    public Optional<List<ObjectPath>> getCollections() {
        return getProperty("Collections").flatMap(variant ->
                variant == null ? Optional.empty() : Optional.ofNullable((ArrayList<ObjectPath>) variant.getValue())
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

    public Session getSession() {
        return session;
    }

}
