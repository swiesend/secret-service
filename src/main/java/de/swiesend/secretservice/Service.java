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
                .flatMap(response -> Optional.of(new Pair<>((Variant<byte[]>) response[0], (DBusPath) response[1])))
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
        return send("Unlock", "ao", objects).flatMap(response ->
                (Static.Utils.isNullOrEmpty(response) || response.length != 2) ?
                        Optional.empty() :
                        Optional.of(new Pair<List<DBusPath>, DBusPath>((List<DBusPath>) response[0], (DBusPath) response[1])));
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
                variant == null ? Optional.empty() : Optional.ofNullable((ArrayList<DBusPath>) variant.getValue())
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
