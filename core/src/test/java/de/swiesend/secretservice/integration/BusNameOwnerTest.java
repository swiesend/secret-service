package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.handlers.BusNameOwner;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link BusNameOwner} knows that nobody owns a name when the bus says so. The bus answers
 * {@code GetNameOwner} for such a name with the error {@code NameHasNoOwner}, which the tracker
 * took as an owner that cannot be read: where the bus's {@code NameOwnerChanged} does not reach
 * it, it never saw that the provider had left, and a wait for a prompt lasted its whole timeout.
 *
 * <p>On a private bus, with a name of the test's own.</p>
 */
class BusNameOwnerTest {

    private static final String NAME = "de.swiesend.secretservice.test.Provider";

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private final List<DBusConnection> connections = new ArrayList<>();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        for (DBusConnection connection : connections) {
            try { connection.disconnect(); } catch (Exception ignored) { }
        }
        harness.stop();
    }

    private DBusConnection connect(String address) throws Exception {
        DBusConnection connection = DBusConnectionBuilder.forAddress(address).withShared(false).build();
        connections.add(connection);
        return connection;
    }

    @Test
    void aNameThatNobodyOwnsIsKnownToHaveNoOwner() throws Exception {
        DBusConnection client = connect(harness.startBus());

        BusNameOwner tracker = BusNameOwner.of(client, NAME);

        assertEquals(Optional.empty(), tracker.read());
        assertFalse(tracker.isOwner(client.getUniqueName()));
        assertTrue(tracker.hasLost(client.getUniqueName()), "nobody owns the name, so this client does not");
    }

    @Test
    void aProviderThatLeftIsSeenWhereTheBusAnnouncesNoChange() throws Exception {
        String address = harness.startBusThatRefusesMatchRules();
        DBusConnection provider = connect(address);
        DBusConnection client = connect(address);
        provider.requestBusName(NAME);
        BusNameOwner tracker = BusNameOwner.of(client, NAME);
        String owner = tracker.read().orElseThrow();
        assertEquals(provider.getUniqueName(), owner);
        assertFalse(tracker.hasLost(owner));

        provider.releaseBusName(NAME);

        // No NameOwnerChanged reaches the tracker here, so the next read asks the bus, as a wait
        // does once a second.
        assertEquals(Optional.empty(), tracker.read());
        assertTrue(tracker.hasLost(owner), "the provider left the bus");
        assertFalse(tracker.isOwner(owner));
    }

    @Test
    void anOwnerIsFollowedThroughTheBusAnnouncements() throws Exception {
        String address = harness.startBus();
        DBusConnection provider = connect(address);
        DBusConnection client = connect(address);
        BusNameOwner tracker = BusNameOwner.of(client, NAME);
        assertEquals(Optional.empty(), tracker.read());

        provider.requestBusName(NAME);

        // isOwner() asks the bus nothing: the tracker takes the owner from the announcement.
        for (int i = 0; i < 100 && !tracker.isOwner(provider.getUniqueName()); i++) Thread.sleep(50);
        assertTrue(tracker.isOwner(provider.getUniqueName()), "the new owner, as the bus announced it");
        assertEquals(Optional.of(provider.getUniqueName()), tracker.read());
    }
}
