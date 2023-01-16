package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.*;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import de.swiesend.secretservice.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.DestroyFailedException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static de.swiesend.secretservice.integration.test.Context.label;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class IntegrationTest {

    private Logger log = LoggerFactory.getLogger(getClass());

    @Test
    public void testWithTransportEncryption() throws
            DBusException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            NoSuchPaddingException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException,
            InterruptedException,
            IOException {

        TransportEncryption transportEncryption = new TransportEncryption();
        TransportEncryption.EncryptedSession encryptedSession = transportEncryption
                .initialize()
                .flatMap(i -> i.openSession())
                .flatMap(o -> o.generateSessionKey())
                .orElseThrow(
                        () -> new IOException("Could not initiate transport encryption.")
                );

        String plain = "super secret";
        Secret encrypted = encryptedSession.encrypt(plain);

        byte[] encBase64 = Base64.getEncoder().encode(encrypted.getSecretValue());
        log.info(label("encrypted secret (base64)", new String(encBase64)));

        char[] decrypted = encryptedSession.decrypt(encrypted);
        log.info(label("         decrypted secret", new String(decrypted)));
        assertEquals(plain, new String(decrypted));

        Service service = transportEncryption.getService();
        Session session = transportEncryption.getSession();

        InternalUnsupportedGuiltRiddenInterface noPrompt = new InternalUnsupportedGuiltRiddenInterface(service);
        Secret master = encryptedSession.encrypt("test");
        Collection collection = new Collection("test", service);
        List<String> collections = Static.Convert.toStrings(service.getCollections().get());

        if (collections.contains(collection.getObjectPath())) {
            noPrompt.unlockWithMasterPassword(collection.getPath(), master);
        } else {
            HashMap<String, Variant> properties = new HashMap();
            properties.put("org.freedesktop.Secret.Collection.Label", new Variant("test"));
            ObjectPath collectionPath = noPrompt.createWithMasterPassword(properties, master).get();
            log.info("created collection: " + collectionPath.getPath());
        }

        // create item with secret
        Map<String, String> attributes = new HashMap();
        attributes.put("transport", "encrypted");
        attributes.put("algorithm", "AES");
        attributes.put("bits", "128");
        attributes.put("mode", "CBC");
        attributes.put("padding", "PKCS5");
        attributes.put("prime", "RFC 2409 Second Oakley Group");
        attributes.put("generator", "RFC 2409 Second Oakley Group");
        Map<String, Variant> properties = Item.createProperties("TestItemWithTransportEncryption", attributes);

        if (collection.isLocked()) {
            noPrompt.unlockWithMasterPassword(collection.getPath(), master);
        }

        Pair<ObjectPath, ObjectPath> createItemResponse = collection.createItem(properties, encrypted, true).get();
        log.info("await signal: Collection.ItemCreated");
        Thread.currentThread().sleep(50L);

        ObjectPath itemPath = createItemResponse.a;
        Item item = new Item(itemPath, service);
        Secret actual = item.getSecret(session.getPath()).get();

        assertEquals(encrypted.getSession(), actual.getSession());
        assertEquals(encrypted.getContentType(), actual.getContentType());

        decrypted = encryptedSession.decrypt(actual);
        log.info(label("  decrypted remote secret", new String(decrypted)));
        assertEquals(plain, new String(decrypted));

        // finally close and clear the private key
        transportEncryption.close();
    }
}
