package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.junit.jupiter.api.Assumptions;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Brings up a private D-Bus session with {@link FakeSecretService} on it, and takes it down again.
 *
 * <p>Extracted because two suites had grown verbatim copies of this, and one copy had already lost
 * the two comments that explain <em>why</em> it is shaped this way — the path-based socket and the
 * two separate connections are both load-bearing, and a copy that drops the reasoning is a copy
 * that gets "simplified" back into a bug.</p>
 */
final class FakeProviderFixture {

    private Process bus;
    private Path socket;
    private DBusConnection clientConnection;
    private DBusConnection providerConnection;
    private ServiceInterface service;
    private FakeSecretService fake;

    /** Whether this machine can run these tests at all. */
    static boolean dbusDaemonAvailable() {
        try {
            Process p = new ProcessBuilder("dbus-daemon", "--version")
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    FakeSecretService fake() {
        return fake;
    }

    /**
     * Starts the bus and the fake provider, and opens the fake collection through the library.
     *
     * @param itemLocked whether the fake's single item starts out individually locked
     */
    CollectionInterface start(boolean itemLocked) throws Exception {
        // A PATH-based socket, not the Linux-default abstract one: the
        // dbus-java-transport-native-unixsocket provider only understands unix:path=... . The CI
        // provider images configure their bus the same way, and for the same reason -- see the
        // comment at the top of .github/providers/dbus-up.sh.
        socket = Files.createTempDirectory("fake-provider").resolve("bus");
        Path config = socket.getParent().resolve("session.conf");
        Files.writeString(config, """
                <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
                 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
                <busconfig>
                  <type>session</type>
                  <listen>unix:path=%s</listen>
                  <policy context="default">
                    <allow send_destination="*" eavesdrop="true"/>
                    <allow eavesdrop="true"/>
                    <allow own="*"/>
                  </policy>
                </busconfig>
                """.formatted(socket));

        bus = new ProcessBuilder("dbus-daemon", "--config-file=" + config, "--nofork")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        for (int i = 0; i < 100 && !Files.exists(socket); i++) Thread.sleep(50);
        Assumptions.assumeTrue(Files.exists(socket), "dbus-daemon did not create its socket");

        String address = "unix:path=" + socket;
        // Two connections on the one bus, as a real deployment has. Sharing a single connection
        // makes dbus-java resolve an incoming signal against the interface exported on it, so the
        // provider's own Completed signal fails to map onto the client's Prompt.Completed.
        providerConnection = DBusConnectionBuilder.forAddress(address).build();
        fake = new FakeSecretService(providerConnection, itemLocked);
        fake.export();

        clientConnection = DBusConnectionBuilder.forAddress(address).build();
        // wrap(), not connect(): this fixture owns the connection and the bus process.
        service = SecretService.create(
                        Optional.of(de.swiesend.secretservice.functional.System.wrap(clientConnection)))
                .orElseThrow(() -> new IllegalStateException("could not create the service"));
        SessionInterface session = service.openSession()
                .orElseThrow(() -> new IllegalStateException("could not open a session"));
        return session.collection(FakeSecretService.COLLECTION_LABEL, Optional.empty())
                .orElseThrow(() -> new IllegalStateException("could not open the fake collection"));
    }

    /** Idempotent: the two-phase tests call this mid-test and again from {@code @AfterEach}. */
    void stop() {
        // Before disconnecting: a pending emitter would otherwise fail mid-send and mutate fake
        // state after the test has finished reading it.
        if (fake != null) fake.awaitPendingPrompt();
        try { if (service != null) service.close(); } catch (Exception ignored) { }
        try { if (clientConnection != null) clientConnection.disconnect(); } catch (Exception ignored) { }
        try { if (providerConnection != null) providerConnection.disconnect(); } catch (Exception ignored) { }
        if (bus != null) {
            bus.destroy();
            try {
                // Forcibly, if it will not go quietly: the directory removed below holds the live
                // socket, and deleting it under a running daemon leaks the process.
                if (!bus.waitFor(10, TimeUnit.SECONDS)) bus.destroyForcibly();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            bus = null;
        }
        if (socket != null) {
            try (var paths = Files.walk(socket.getParent())) {
                paths.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (Exception ignored) { }
                });
            } catch (Exception ignored) { }
            socket = null;
        }
        service = null;
        clientConnection = null;
        providerConnection = null;
        fake = null;
    }
}
