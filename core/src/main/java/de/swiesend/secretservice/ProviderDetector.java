package de.swiesend.secretservice;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.interfaces.DBus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Detects which Secret Service provider is currently serving
 * {@code org.freedesktop.secrets} on the session D-Bus.
 *
 * <h3>Detection strategy</h3>
 * <ol>
 *   <li>Resolve the unique bus name (e.g. {@code :1.241}) of the
 *       {@code org.freedesktop.secrets} owner via {@code GetNameOwner}.</li>
 *   <li>For each known provider, check whether one of its well-known names
 *       is held by the <em>same</em> unique owner.  This correctly handles
 *       Flatpak-sandboxed KeePassXC, which registers
 *       {@code org.keepassxc.KeePassXC.MainWindow} (not
 *       {@code org.keepassxc.KeePassXC}) on the host session bus.</li>
 *   <li>Fall back to {@link Provider#UNKNOWN} when {@code org.freedesktop.secrets}
 *       is present but no known provider matches.</li>
 * </ol>
 */
public final class ProviderDetector {

    private static final Logger log = LoggerFactory.getLogger(ProviderDetector.class);

    private ProviderDetector() {}

    // ── Provider identity ─────────────────────────────────────────────────

    /**
     * Known Secret Service providers with their canonical display name and the
     * D-Bus well-known names they are expected to register.
     */
    public enum Provider {

        /**
         * KeePassXC — may register either the bare name (native install) or only
         * the {@code .MainWindow} sub-name (Flatpak sandbox).  Both are checked.
         */
        KEEPASSXC(
                "KeePassXC",
                "org.keepassxc.KeePassXC",
                "org.keepassxc.KeePassXC.MainWindow"
        ),

        /** GNOME Keyring daemon. */
        GNOME_KEYRING(
                "gnome-keyring",
                "org.gnome.keyring",
                "org.gnome.keyring.SystemPrompter"
        ),

        /**
         * KDE Wallet.  On modern Plasma the Secret Service API is served by the
         * standalone {@code ksecretd} daemon (registering {@code org.kde.ksecretd}
         * / {@code org.kde.secretservicecompat}), which runs as a <em>separate</em>
         * process from {@code kwalletd5}/{@code kwalletd6}.  All of these names are
         * checked so detection works whether secrets come from ksecretd or, on
         * older setups, directly from kwalletd.
         */
        KWALLET(
                "KWallet",
                "org.kde.ksecretd",
                "org.kde.secretservicecompat",
                "org.kde.kwalletd6",
                "org.kde.kwalletd5"
        ),

        /**
         * {@code org.freedesktop.secrets} is present but could not be matched
         * to any known provider.
         */
        UNKNOWN("unknown"),

        /** {@code org.freedesktop.secrets} is not present, or the connection is unavailable. */
        UNAVAILABLE("N/A");

        /** Human-readable display name (returned by {@link ProviderDetector#detect}). */
        public final String displayName;

        /** D-Bus well-known names that uniquely identify this provider. */
        public final String[] busNames;

        Provider(String displayName, String... busNames) {
            this.displayName = displayName;
            this.busNames    = busNames;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }

    // ── Well-known D-Bus constants ────────────────────────────────────────

    /** Standard well-known name for the Secret Service API. */
    public static final String SECRETS_BUS_NAME = "org.freedesktop.secrets";

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Detects the active Secret Service provider and returns its display name.
     *
     * @param conn an active D-Bus session connection
     * @return display name of the detected provider (e.g. {@code "KeePassXC"},
     *         {@code "gnome-keyring"}, {@code "N/A"})
     */
    public static String detect(DBusConnection conn) {
        return detectProvider(conn).displayName;
    }

    /**
     * Detects the active Secret Service provider and returns the full
     * {@link Provider} enum constant.
     *
     * @param conn an active D-Bus session connection
     * @return the detected {@link Provider}
     */
    public static Provider detectProvider(DBusConnection conn) {
        if (conn == null || !conn.isConnected()) return Provider.UNAVAILABLE;
        try {
            DBus bus = conn.getRemoteObject(
                    "org.freedesktop.DBus", "/org/freedesktop/DBus", DBus.class);

            Set<String> active = new HashSet<>(Arrays.asList(bus.ListNames()));

            if (!active.contains(SECRETS_BUS_NAME)) {
                return Provider.UNAVAILABLE;
            }

            // Resolve the unique owner of org.freedesktop.secrets (e.g. ":1.241").
            // We then check whether the same unique owner also holds one of the
            // known provider's well-known names — this correctly handles
            // Flatpak-proxied KeePassXC which only registers
            // "org.keepassxc.KeePassXC.MainWindow" (not "org.keepassxc.KeePassXC").
            String secretsOwner = bus.GetNameOwner(SECRETS_BUS_NAME);

            for (Provider candidate : new Provider[]{
                    Provider.KEEPASSXC, Provider.GNOME_KEYRING, Provider.KWALLET}) {
                for (String name : candidate.busNames) {
                    if (!active.contains(name)) continue;
                    try {
                        String nameOwner = bus.GetNameOwner(name);
                        if (secretsOwner.equals(nameOwner)) {
                            log.debug("Detected provider {} - shared unique owner {} ({} == {})", // log-check: allow bus name from the Provider enum, not user data
                                    candidate.displayName, secretsOwner, SECRETS_BUS_NAME, name);
                            return candidate;
                        }
                    } catch (Exception ex) {
                        log.trace("GetNameOwner({}) failed: {}", name, ex.getMessage()); // log-check: allow bus name from the Provider enum, not user data
                    }
                }
            }

            return Provider.UNKNOWN;

        } catch (Exception e) {
            log.warn("Provider detection failed: {}", e.getMessage());
            return Provider.UNAVAILABLE;
        }
    }
}
