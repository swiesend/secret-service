package de.swiesend.secret.functional;

import de.swiesend.secret.functional.interfaces.ServiceInterface;
import de.swiesend.secret.functional.interfaces.SessionInterface;
import de.swiesend.secret.functional.interfaces.SystemInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBus;
import org.freedesktop.secret.Pair;
import org.freedesktop.secret.Service;
import org.freedesktop.secret.Static;
import org.freedesktop.secret.TransportEncryption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;


enum Activatable {
    DBUS(Static.DBus.Service.DBUS),
    SECRETS(Static.Service.SECRETS),
    GNOME_KEYRING(org.gnome.keyring.Static.Service.KEYRING);

    public final String name;

    Activatable(String name) {
        this.name = name;
    }

}

class AvailableServices {

    private static final Logger log = LoggerFactory.getLogger(AvailableServices.class);

    public EnumSet<Activatable> services = EnumSet.noneOf(Activatable.class);

    public AvailableServices(System system) {
        DBusConnection connection = system.getConnection();
        if (connection.isConnected()) {
            try {
                DBus bus = connection.getRemoteObject(
                        Static.DBus.Service.DBUS,
                        Static.DBus.ObjectPaths.DBUS,
                        DBus.class);
                List<String> activatableServices = Arrays.asList(bus.ListActivatableNames());

                if (!activatableServices.contains(Static.DBus.Service.DBUS)) {
                    log.error("Missing D-Bus service: " + Static.DBus.Service.DBUS);
                } else {
                    services.add(Activatable.DBUS);
                }

                if (!activatableServices.contains(Static.Service.SECRETS)) {
                    log.error("Missing D-Bus service: " + Static.Service.SECRETS);
                } else {
                    services.add(Activatable.SECRETS);
                }
                if (!activatableServices.contains(org.gnome.keyring.Static.Service.KEYRING)) {
                    log.warn("Proceeding without D-Bus service: " + org.gnome.keyring.Static.Service.KEYRING);
                } else {
                    services.add(Activatable.GNOME_KEYRING);
                }
            } catch (DBusException | ExceptionInInitializerError e) {
                log.warn("The secret service is not available. You may want to install the `gnome-keyring` package. Is the `gnome-keyring-daemon` running?", e);
            }
        }
    }


}

public class SecretService extends ServiceInterface {

    private static final Logger log = LoggerFactory.getLogger(SecretService.class);
    private Map<UUID, SessionInterface> sessions = new HashMap<>();
    private org.freedesktop.secret.Service service = null;

    // TODO: remove unnecessary fields
    // private Prompt prompt = null;
    // private InternalUnsupportedGuiltRiddenInterface withoutPrompt = null;
    // private org.freedesktop.secret.Session session = null;
    private boolean isOrgGnomeKeyringAvailable = false;

    private SecretService(SystemInterface system, AvailableServices available) {
        this.service = new Service(system.getConnection());
        this.isOrgGnomeKeyringAvailable = available.services.contains(Activatable.GNOME_KEYRING);
    }

    /**
     * Create a Secret-Service instance with initialized transport encryption.
     */
    public static Optional<ServiceInterface> create() {
        return System.connect()
                .map(system -> new Pair<>(system, new AvailableServices(system)))
                .filter(pair -> isAvailable(pair.a, pair.b))
                .map(pair -> new SecretService(pair.a, pair.b));
    }

    /**
     * Checks if all necessary D-Bus services are provided by the system:<br>
     * <code>org.freedesktop.DBus</code><br>
     * <code>org.freedesktop.secrets</code><br>
     * <code>org.gnome.keyring<code>
     *
     * @return true if the secret service is available, otherwise false and will log an error message.
     */
    private static boolean isAvailable(System system, AvailableServices available) {
        DBusConnection connection = system.getConnection();
        if (connection.isConnected()) {
            try {
                if (!available.services.contains(Activatable.DBUS)) {
                    log.error("Missing D-Bus service: " + Activatable.DBUS.name);
                    return false;
                }
                if (!available.services.contains(Activatable.SECRETS)) {
                    log.error("Missing D-Bus service: " + Activatable.SECRETS.name);
                    return false;
                }
                if (!available.services.contains(Activatable.GNOME_KEYRING)) {
                    log.warn("Proceeding without D-Bus service: " + Activatable.GNOME_KEYRING.name);
                }

                // The following calls intent to open a session without actually generating a full session.
                // Necessary in order to check if the provided 'secret service' supports the expected transport
                // encryption algorithm (DH_IETF1024_SHA256_AES128_CBC_PKCS7) or raises an error, like
                // "org.freedesktop.DBus.Error.ServiceUnknown <: org.freedesktop.dbus.exceptions.DBusException"
                TransportEncryption transport = new TransportEncryption(connection);
                boolean isSessionSupported = transport
                        .initialize()
                        .flatMap(init -> init.openSession())
                        .isPresent();
                transport.close();

                return isSessionSupported;
            } catch (ExceptionInInitializerError e) {
                log.warn("The secret service is not available. " +
                        "You may want to install the `gnome-keyring` package. Is the `gnome-keyring-daemon` running?", e);
                return false;
            }
        } else {
            log.error("No D-Bus connection: Cannot check if all needed services are available.");
            return false;
        }
    }

    @Override
    public boolean isOrgGnomeKeyringAvailable() {
        return isOrgGnomeKeyringAvailable;
    }

    @Override
    public boolean clear() {
        return false;
    }

    @Override
    public Optional<Session> openSession() {
        return Session.open(this);
    }

    public void registerSession(Session session) {
        this.sessions.put(session.getId(), session);
    }

    public void unregisterSession(Session session) {
        this.sessions.remove(session.getId());
    }

    @Override
    public List<SessionInterface> getSessions() {
        return this.sessions.values().stream().toList();
    }

    /*@Override
    public SystemInterface getSystem() {
        return this.system;
    }*/

    @Override
    public Duration getTimeout() {
        return null;
    }

    @Override
    public void setTimeout(Duration timeout) {

    }

    @Override
    public void close() throws Exception {

    }

    public Service getService() {
        return service;
    }
}
