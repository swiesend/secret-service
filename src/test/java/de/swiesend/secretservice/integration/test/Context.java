package de.swiesend.secretservice.integration.test;

import de.swiesend.secretservice.*;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.slf4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.System.exit;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Context {

    public Logger log;
    public boolean encrypted;

    public TransportEncryption.EncryptedSession encryption = null;
    public Service service = null;
    public Session session = null;
    public Secret password = null;
    public InternalUnsupportedGuiltRiddenInterface withoutPrompt = null;
    public Prompt prompt = null;
    public List<String> collections = null;
    public Collection collection = null;
    public Item item = null;

    public Context(Logger log) {
        this.log = log;
        this.encrypted = true;
    }

    public Context(Logger log, boolean encrypted) {
        this.log = log;
        this.encrypted = encrypted;
    }

    public static String label(String name, String msg) {
        return name + ": \"" + msg + "\"";
    }

    public static String label(String name, int number) {
        return name + ": " + number;
    }

    public static String label(String name, long number) {
        return name + ": " + number;
    }

    public static String label(String name, BigInteger number) {
        return name + ": " + number;
    }

    public static String label(String name, byte[] bytes) {
        return name + ": " + Arrays.toString(bytes);
    }

    public static String label(String name, List list) {
        return name + ": " + Arrays.toString(list.toArray());
    }

    public void ensureService() {
        DBusConnection connection = null;
        try {
            connection = DBusConnectionBuilder.forSessionBus().withShared(false).build();
        } catch (DBusException | RuntimeException e) {
            log.error("Could not connect to the D-Bus", e);
            exit(-1);
        }
        service = new Service(connection);
        withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(service);
        prompt = new Prompt(service);
    }

    public void ensureSession() throws RuntimeException {
        ensureService();

        try {
            if (encrypted) {
                encryption = new TransportEncryption(service)
                        .initialize()
                        .flatMap(i -> i.openSession())
                        .flatMap(o -> o.generateSessionKey())
                        .orElseThrow(
                                () -> new IOException("Could not initiate transport encryption.")
                        );
                session = encryption.getSession();
            } else {
                Pair<Variant<byte[]>, ObjectPath> pair = service.openSession(Static.Algorithm.PLAIN, new Variant("")).get();
                session = new Session(pair.b, service);
            }
        } catch (Exception e) {
            log.error("Could not establish transport encryption.", e);
            exit(-2);
        }

        log.info(session.getObjectPath());
        assertNotNull(session);
        assertTrue(session.getObjectPath().startsWith(Static.ObjectPaths.SESSION + "/s"));

        String test = "test";
        if (encrypted) {
            try {
                password = encryption.encrypt(test);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                     InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            }
        } else {
            password = new Secret(session.getPath(), "".getBytes(), test.getBytes());
        }
    }

    public void ensureCollection() {
        ensureSession();

        collection = new Collection("test", service);

        collections = Static.Convert.toStrings(service.getCollections().get());
        if (collections.contains(Static.ObjectPaths.collection("test"))) {
            ObjectPath deletePrompt = collection.delete().get();
            if (!deletePrompt.getPath().equals("/")) {
                log.error("won't wait for prompt in automated test context.");
                exit(-3);
            }
        }
        Map<String, Variant> properties = Collection.createProperties("test");
        withoutPrompt.createWithMasterPassword(properties, password);
        collections = Static.Convert.toStrings(service.getCollections().get());

        if (collection.isLocked()) {
            withoutPrompt.unlockWithMasterPassword(collection.getPath(), password);
        }
    }

    public void ensureItem() {
        ensureCollection();

        Map<String, String> attributes = new HashMap();
        attributes.put("Attribute1", "Value1");
        attributes.put("Attribute2", "Value2");

        String plain = "super secret";
        Secret secret = null;

        if (encrypted) {
            try {
                secret = encryption.encrypt(plain);
                attributes.put("TransportEncryption", "yes");
            } catch (Exception e) {
                log.error("Could not encrypt the secret.", e);
                exit(-4);
            }
        } else {
            attributes.put("TransportEncryption", "no");
            secret = new Secret(session.getPath(), plain.getBytes());
        }

        if (collection.isLocked()) {
            withoutPrompt.unlockWithMasterPassword(collection.getPath(), password);
        }

        List<ObjectPath> items = collection.getItems().get();
        for (ObjectPath path : items) {
            Item i = new Item(path, service);
            i.delete();
        }

        Map<String, Variant> properties = Item.createProperties("TestItem", attributes);
        Pair<ObjectPath, ObjectPath> response = collection.createItem(properties, secret, true).get();
        ObjectPath itemPath = response.a;

        item = new Item(itemPath, service);
    }

    public void after() {
        try {
            service.getConnection().disconnect();
            Thread.currentThread().sleep(150L);
        } catch (InterruptedException e) {
            log.error("Could not disconnect properly from the D-Bus.", e);
        }
    }


}
