package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Issue #45: a provider may lock items <b>individually</b>, and the client must then unlock the item
 * before reading it. The library only unlocked the collection, so on KeePassXC a read of a locked
 * item failed.
 *
 * <p>No provider in CI reproduces this. gnome-keyring never locks a single item, and the KeePassXC
 * container sets {@code ConfirmAccessItem=false}, which switches the behaviour off. These tests
 * therefore run against {@link FakeSecretService} on a private session bus: a provider that locks
 * one item and clears it only when {@code Unlock} names that item's own path.</p>
 *
 * <p>The suite skips when {@code dbus-daemon} is not on the PATH.</p>
 */
class PerItemUnlockTest {

    private Process bus;
    private String busAddress;
    private java.nio.file.Path socket;
    private DBusConnection connection;
    private DBusConnection providerConnection;
    private FakeSecretService fake;
    private ServiceInterface service;

    private static boolean dbusDaemonAvailable() {
        try {
            return new ProcessBuilder("dbus-daemon", "--version").start().waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private void start(boolean itemLocked) throws Exception {
        // A PATH-based socket, not the Linux-default abstract one: the
        // dbus-java-transport-native-unixsocket provider only understands unix:path=... . The CI
        // provider images configure their bus the same way, and for the same reason -- see the
        // comment at the top of .github/providers/dbus-up.sh.
        socket = java.nio.file.Files.createTempDirectory("per-item-unlock").resolve("bus");
        java.nio.file.Path config = socket.getParent().resolve("session.conf");
        java.nio.file.Files.writeString(config, """
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
                .redirectErrorStream(true).start();
        busAddress = "unix:path=" + socket;
        for (int i = 0; i < 100 && !java.nio.file.Files.exists(socket); i++) Thread.sleep(50);
        Assumptions.assumeTrue(java.nio.file.Files.exists(socket),
                "dbus-daemon did not create its socket at " + socket);

        // Two connections on the one bus, as a real deployment has. Sharing a single connection
        // makes dbus-java resolve an incoming signal against the interface exported on it, so the
        // provider's own Completed signal fails to map onto the client's Prompt.Completed.
        providerConnection = DBusConnectionBuilder.forAddress(busAddress).build();
        fake = new FakeSecretService(providerConnection, itemLocked);
        fake.export();

        connection = DBusConnectionBuilder.forAddress(busAddress).build();
        // wrap(), not connect(): the test owns the connection and the bus process.
        service = SecretService.create(
                        Optional.of(de.swiesend.secretservice.functional.System.wrap(connection)))
                .orElseThrow(() -> new IllegalStateException("could not create the service"));
    }

    private CollectionInterface fakeCollection() {
        SessionInterface session = service.openSession()
                .orElseThrow(() -> new IllegalStateException("could not open a session"));
        return session.collection(FakeSecretService.COLLECTION_LABEL, Optional.empty())
                .orElseThrow(() -> new IllegalStateException("could not open the fake collection"));
    }

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(dbusDaemonAvailable(), "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        try { if (service != null) service.close(); } catch (Exception ignored) { }
        try { if (connection != null) connection.disconnect(); } catch (Exception ignored) { }
        try { if (providerConnection != null) providerConnection.disconnect(); } catch (Exception ignored) { }
        if (bus != null) bus.destroy();
    }

    @Test
    void aLockedItemIsUnlockedAutomaticallyAndThenRead() throws Exception {
        start(true);
        CollectionInterface collection = fakeCollection();

        Optional<char[]> secret = collection.getSecret(FakeSecretService.ITEM_PATH);

        assertTrue(secret.isPresent(), "a locked item must be unlocked and then read");
        assertEquals(FakeSecretService.SECRET_VALUE, new String(secret.get()));
        assertTrue(fake.unlockCalls().contains(FakeSecretService.ITEM_PATH),
                "the ITEM's own path must be unlocked; unlock calls were " + fake.unlockCalls());
        assertFalse(fake.isItemLocked(), "the item is unlocked afterwards");
    }

    @Test
    void unlockingTheCollectionAloneDoesNotReachTheItem() throws Exception {
        // The discrimination test. Before the fix the client unlocked only the collection, which
        // this fake deliberately treats as a no-op for the item -- exactly as KeePassXC does -- so
        // the read fell through to GetSecret on a locked item and failed.
        start(true);
        CollectionInterface collection = fakeCollection();

        assertTrue(collection.unlockWithUserPermission(), "the collection unlocks as before");
        assertTrue(fake.isItemLocked(),
                "precondition: a collection-level unlock must leave the item locked");

        assertTrue(collection.getSecret(FakeSecretService.ITEM_PATH).isPresent(),
                "the read must still succeed, which is only possible if the ITEM was unlocked too");
    }

    @Test
    void aDismissedPromptReturnsEmptyRatherThanFailingLater() throws Exception {
        // NOT a discrimination test: without the fix the read also comes back empty, because
        // GetSecret on a locked item fails anyway. What this pins is the *manner* of the failure --
        // an empty Optional rather than an exception or a hang -- and that a refusal leaves the item
        // locked instead of being reported as an unreadable secret.
        start(true);
        CollectionInterface collection = fakeCollection();
        fake.setDismissPrompts(true);

        Optional<char[]> secret = collection.getSecret(FakeSecretService.ITEM_PATH);

        assertTrue(secret.isEmpty(), "a refused unlock must report no secret, not throw or hang");
        assertTrue(fake.isItemLocked(), "the item stays locked when the user refuses");
    }

    @Test
    void anUnlockedItemIsNeverUnlockedAgain() throws Exception {
        // NOT a discrimination test either -- it passes before the fix, trivially, because the code
        // it guards did not exist. That is precisely its job: it is the regression guard for
        // existing consumers such as Cryptomator on gnome-keyring, where items are never locked
        // individually. The new path must not run at all: no extra D-Bus call, and no prompt that
        // did not appear before.
        start(false);
        CollectionInterface collection = fakeCollection();

        Optional<char[]> secret = collection.getSecret(FakeSecretService.ITEM_PATH);

        assertTrue(secret.isPresent(), "an unlocked item reads as it always did");
        assertEquals(FakeSecretService.SECRET_VALUE, new String(secret.get()));
        assertTrue(fake.unlockCalls().stream().noneMatch(FakeSecretService.ITEM_PATH::equals),
                "no item-level unlock may be attempted; unlock calls were " + fake.unlockCalls());
    }
}
