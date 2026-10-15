package de.swiesend.secretservice.functional.interfaces;

import de.swiesend.secretservice.TransportEncryption;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

public interface ServiceInterface extends AutoCloseable {

    Logger log = LoggerFactory.getLogger(ServiceInterface.class);

    /**
     * Checks if all necessary D-Bus services are provided by the system:<br>
     * <code>org.freedesktop.DBus</code><br>
     * <code>org.freedesktop.secrets</code><br>
     * <code>org.gnome.keyring</code>
     *
     * @return true if the secret service is available, otherwise false and will log an error message.
     */
    static boolean isAvailable(SystemInterface system, AvailableServices available) {
        if (system == null || available == null) {
            log.error("Cannot check availability: system and available must not be null.");
            return false;
        }
        DBusConnection connection = system.getConnection();
        if (connection.isConnected()) {
            try {
                if (!available.services.contains(Activatable.DBUS)) {
                    log.error("Missing required D-Bus service: " + Activatable.DBUS.name);
                    return false;
                }
                if (!available.services.contains(Activatable.SECRETS)) {
                    log.error("Missing required D-Bus service: " + Activatable.SECRETS.name);
                    return false;
                }
                if (!available.services.contains(Activatable.GNOME_KEYRING)) {
                    log.warn("Proceeding without optional D-Bus service: " + Activatable.GNOME_KEYRING.name);
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

    Optional<SessionInterface> openSession();

    List<SessionInterface> getSessions();

    /**
     * Detects the currently active Secret Service provider and returns its display name.
     *
     * @return display name such as {@code "KeePassXC"}, {@code "gnome-keyring"},
     *         {@code "unknown"}, or {@code "N/A"}
     * @see de.swiesend.secretservice.ProviderDetector
     */
    String getProvider();

    /**
     * Detects the currently active Secret Service provider as a typed enum constant.
     *
     * @return the detected {@link de.swiesend.secretservice.ProviderDetector.Provider}
     */
    de.swiesend.secretservice.ProviderDetector.Provider detectProvider();

    /** How long the library waits for the user to answer a prompt; see {@link #setTimeout}. */
    Duration getTimeout();

    /**
     * Sets how long the library waits for the user to answer a prompt, 120 seconds by default. The
     * wait for the reply to a call is set apart, with {@link #setReplyTimeout}.
     */
    void setTimeout(Duration timeout);

    /** How long a call waits for the provider's reply; see {@link #setReplyTimeout}. */
    default Duration getReplyTimeout() {
        return getService().getMessageHandler().getReplyTimeout();
    }

    /**
     * Sets how long a call waits for the provider's reply: every call of this service, of its
     * sessions, and of the collections and items opened with them, also those open already. A
     * call without a reply by then fails as one to a provider that is not there.
     *
     * <p>2 seconds by default. A provider that waits for the user before it answers needs
     * longer: KeePassXC answers a call on a locked database only once the user has unlocked it.
     * libsecret waits 25 seconds. A call ends earlier when the connection closes or the provider
     * quits.</p>
     *
     * @param timeout at least a millisecond. A duration too long for a count of milliseconds
     *                waits without end.
     * @throws NullPointerException     if {@code timeout} is null
     * @throws IllegalArgumentException if {@code timeout} is shorter than a millisecond
     * @see de.swiesend.secretservice.handlers.MessageHandler#setReplyTimeout
     */
    default void setReplyTimeout(Duration timeout) {
        getService().getMessageHandler().setReplyTimeout(timeout);
    }

    de.swiesend.secretservice.Service getService();

    boolean isGnomeKeyringAvailable();
}
