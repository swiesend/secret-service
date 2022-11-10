package de.swiesend.secret.functional;

import de.swiesend.secret.functional.interfaces.CollectionInterface;
import de.swiesend.secret.functional.interfaces.ServiceInterface;
import de.swiesend.secret.functional.interfaces.SessionInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.*;
import org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;

import static org.freedesktop.secret.Static.DEFAULT_PROMPT_TIMEOUT;

public class Collection implements CollectionInterface {

    private static final Logger log = LoggerFactory.getLogger(Collection.class);
    /*this.prompt = new Prompt(service);
      this.withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(service);
      */
    org.freedesktop.secret.Collection collection = null;
    SessionInterface session = null;
    ServiceInterface service = null;
    DBusConnection connection = null;
    private Duration timeout = DEFAULT_PROMPT_TIMEOUT;
    private Boolean isUnlockedOnceWithUserPermission = false;
    private String label = null;
    private Secret encrypted = null;
    private Prompt prompt = null;

    public Collection(SessionInterface session, String label, CharSequence password) {
        init(session);
        this.label = label;
        try {
            this.encrypted = session.getEncryptedSession().encrypt(password);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }

    public Collection(SessionInterface session) {
        init(session);
    }

    private void init(SessionInterface session) {
        this.session = session;
        ObjectPath path = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        collection = new org.freedesktop.secret.Collection(path, session.getService().getService());
        prompt = new Prompt(session.getService().getService());
        log.info(collection.getId());
        this.service = session.getService();
        this.connection = service.getService().getConnection();
    }

    @Override
    public boolean clear() {
        return false;
    }

    @Override
    public Optional<String> createItem(String label, CharSequence password) {
        return Optional.empty();
    }

    @Override
    public Optional<String> createItem(String label, CharSequence password, Map<String, String> attributes) {
        if (Static.Utils.isNullOrEmpty(password)) {
            throw new IllegalArgumentException("The password may not be null or empty.");
        }
        if (label == null) {
            throw new IllegalArgumentException("The label of the item may not be null.");
        }

        if (collection == null || session.getEncryptedSession() == null) return Optional.empty();

        unlock();

        DBusPath item = null;
        final Map<String, Variant> properties = Item.createProperties(label, attributes);
        try (final Secret secret = session.getEncryptedSession().encrypt(password)) {
            Pair<ObjectPath, ObjectPath> response = collection.createItem(properties, secret, false).get();
            if (response == null) return null;
            item = response.a;
            if ("/".equals(item.getPath())) {
                org.freedesktop.secret.interfaces.Prompt.Completed completed = prompt.await(response.b);
                if (!completed.dismissed) {
                    org.freedesktop.secret.Collection.ItemCreated ic = collection
                            .getSignalHandler()
                            .getLastHandledSignal(org.freedesktop.secret.Collection.ItemCreated.class);
                    item = ic.item;
                }
            }
        } catch (NoSuchAlgorithmException |
                 NoSuchPaddingException |
                 InvalidAlgorithmParameterException |
                 InvalidKeyException |
                 BadPaddingException |
                 IllegalBlockSizeException e) {
            log.error("Cloud not encrypt the secret.", e);
        }

        if (null != item) {
            return Optional.of(item.getPath());
        } else {
            return Optional.empty();
        }
    }

    @Override
    public boolean delete() {
        return false;
    }

    @Override
    public boolean deleteItem(String objectPath) {
        return false;
    }

    @Override
    public boolean deleteItems(List<String> objectPaths) {
        return false;
    }

    @Override
    public Optional<Map<String, String>> getAttributes(String objectPath) {
        return Optional.empty();
    }

    @Override
    public Optional<List<String>> getItems(Map<String, String> attributes) {
        return Optional.empty();
    }

    @Override
    public Optional<String> getLabel(String objectPath) {
        return Optional.empty();
    }

    @Override
    public Optional<String> setLabel(String objectPath) {
        return Optional.empty();
    }

    @Override
    public Optional<char[]> getSecret(String objectPath) {
        if (Static.Utils.isNullOrEmpty(objectPath)) return Optional.empty();
        unlock();

        final Item item = getItem(objectPath);

        char[] decrypted = null;
        ObjectPath sessionPath = session.getSession().getPath();
        try (final Secret secret = item.getSecret(sessionPath).orElseGet(() -> new Secret(sessionPath, null))) {
            decrypted = session.getEncryptedSession().decrypt(secret);
        } catch (NoSuchPaddingException |
                 NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException |
                 InvalidKeyException |
                 BadPaddingException |
                 IllegalBlockSizeException e) {
            log.error("Could not decrypt the secret.", e);
            return Optional.empty();
        }
        if (decrypted == null) {
            return Optional.empty();
        } else {
            return Optional.of(decrypted);
        }
    }

    @Override
    public Optional<Map<String, char[]>> getSecrets() {
        return Optional.empty();
    }

    @Override
    public boolean isLocked() {
        return false;
    }

    @Override
    public boolean lock() {
        return false;
    }

    private void unlock() {
        if (collection != null && collection.isLocked()) {
            if (encrypted == null || isDefault()) {
                Pair<List<ObjectPath>, ObjectPath> response = service.getService().unlock(lockable()).get();
                performPrompt(response.b);
                if (!collection.isLocked()) {
                    isUnlockedOnceWithUserPermission = true;
                    log.info("Unlocked collection: \"" + collection.getLabel().get() + "\" (" + collection.getObjectPath() + ")");
                }
            } else if (service.isOrgGnomeKeyringAvailable()) {
                InternalUnsupportedGuiltRiddenInterface withoutPrompt = new InternalUnsupportedGuiltRiddenInterface(service.getService());
                withoutPrompt.unlockWithMasterPassword(collection.getPath(), encrypted);
                log.debug("Unlocked collection: \"" + collection.getLabel().get() + "\" (" + collection.getObjectPath() + ")");
            }
        }
    }

    @Override
    public boolean unlockWithUserPermission() {
        return false;
    }

    @Override
    public boolean updateItem(String objectPath, String label, CharSequence password, Map<String, String> attributes) {
        return false;
    }

    @Override
    public void close() throws Exception {

    }

    private Map<ObjectPath, String> getLabels() {
        List<ObjectPath> collections = service.getService().getCollections().get();

        Map<ObjectPath, String> labels = new HashMap();
        for (ObjectPath path : collections) {
            org.freedesktop.secret.Collection c = new org.freedesktop.secret.Collection(path, service.getService(), null);
            labels.put(path, c.getLabel().get());
        }

        return labels;
    }

    private boolean exists(String label) {
        Map<ObjectPath, String> labels = getLabels();
        return labels.containsValue(label);
    }

    private ObjectPath getCollectionPath(String label) {
        Map<ObjectPath, String> labels = getLabels();

        ObjectPath path = null;
        for (Map.Entry<ObjectPath, String> entry : labels.entrySet()) {
            ObjectPath p = entry.getKey();
            String l = entry.getValue();
            if (label.equals(l)) {
                path = p;
                break;
            }
        }
        return path;
    }

    private boolean isDefault() {
        if (connection != null && connection.isConnected()) {
            List<String> defaults = Arrays.asList(null, "login", "session", "default");
            return defaults.contains(collection.getId());
        } else {
            log.error("No D-Bus connection: Cannot check if the collection is the default collection.");
            return false;
        }
    }

    private void performPrompt(ObjectPath path) {
        if (!("/".equals(path.getPath()))) {
            prompt.await(path, timeout);
        }
    }

    private Item getItem(String path) {
        if (path != null) {
            return new Item(Static.Convert.toObjectPath(path), service.getService());
        } else {
            return null;
        }
    }

    private List<ObjectPath> lockable() {
        return Arrays.asList(collection.getPath());
    }
}
