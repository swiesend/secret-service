package de.swiesend.secret.functional.interfaces;

import de.swiesend.secret.functional.System;
import de.swiesend.secretservice.TransportEncryption;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

public abstract class ServiceInterface implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(ServiceInterface.class);

    public static Optional<ServiceInterface> create() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    synchronized public static boolean disconnect() {
        log.warn("Do not call the interface method, but the implementation.");
        return false;
    }

    private static Optional<DBusConnection> getConnection() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    public static boolean isConnected() {
        log.warn("Do not call the interface method, but the implementation.");
        return false;
    }

    private static Optional<Thread> setupShutdownHook() {
        log.warn("Do not call the interface method, but the implementation.");
        return Optional.empty();
    }

    /**
     * Checks if all necessary D-Bus services are provided by the system:<br>
     * <code>org.freedesktop.DBus</code><br>
     * <code>org.freedesktop.secrets</code><br>
     * <code>org.gnome.keyring<code>
     *
     * @return true if the secret service is available, otherwise false and will log an error message.
     */
    public static boolean isAvailable(System system, AvailableServices available) {
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
                        .flatMap(TransportEncryption.InitializedSession::openSession)
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

    abstract public Optional<SessionInterface> openSession();

    abstract public List<SessionInterface> getSessions();

    abstract public Duration getTimeout();

    abstract public void setTimeout(Duration timeout);

    abstract public de.swiesend.secretservice.Service getService();

    abstract public boolean isOrgGnomeKeyringAvailable();
}
