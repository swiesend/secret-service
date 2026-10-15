package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Item;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.handlers.MessageHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * How long a call waits for the provider's reply is a setting of the service, which the objects
 * opened with it share, also those open already. A provider that waits for the user before it
 * answers outlasts the default of 2 seconds: KeePassXC with a locked database.
 *
 * <p>Against {@link FakeSecretService}, whose stalled reads answer after
 * {@link FakeSecretService#STALL}, 3.5 seconds.</p>
 */
class ReplyTimeoutTest {

    private static final Duration LONGER = Duration.ofSeconds(10);

    private final FakeProviderFixture harness = new FakeProviderFixture();

    @AfterEach
    void stop() {
        // Before the teardown, which reads properties too.
        if (harness.fake() != null) {
            harness.fake().setStallItemProperties(false);
            harness.fake().setStallCollectionProperties(false);
        }
        harness.stop();
    }

    private CollectionInterface start() throws Exception {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(), "dbus-daemon is not on the PATH");
        return harness.start(false);
    }

    private ServiceInterface service() {
        return harness.session().getService();
    }

    private Item item() {
        return new Item(Static.Convert.toObjectPath(FakeSecretService.ITEM_PATH), harness.rawService());
    }

    @Test
    void aSlowReplyArrivesWithinALongerTimeout() throws Exception {
        start();
        Item item = item();
        harness.fake().setStallItemProperties(true);

        assertEquals(Static.DEFAULT_REPLY_TIMEOUT, service().getReplyTimeout());
        assertEquals(Optional.empty(), item.exists(), "the default timeout passes before the reply");

        service().setReplyTimeout(LONGER);
        long start = java.lang.System.nanoTime();

        assertEquals(Optional.of(true), item.exists(), "the item made before the setting waits longer too");
        assertTrue(java.lang.System.nanoTime() - start >= FakeSecretService.STALL.toNanos(),
                "the read was stalled");
        assertEquals(LONGER, service().getReplyTimeout());
    }

    @Test
    void theCollectionsAndItemsOfTheServiceWaitAsLong() throws Exception {
        CollectionInterface collection = start();
        service().setReplyTimeout(LONGER);

        harness.fake().setStallItemProperties(true);
        assertEquals(Optional.of("fake-item"), collection.getItemLabel(FakeSecretService.ITEM_PATH),
                "an item of the collection");
        harness.fake().setStallItemProperties(false);

        // Locked, so that a read without an answer, which counts as unlocked, cannot pass.
        harness.fake().lockCollection();
        harness.fake().setStallCollectionProperties(true);
        assertTrue(collection.isLocked(), "the collection itself");
    }

    @Test
    void aTimeoutTooLongForMillisecondsWaitsWithoutEnd() throws Exception {
        start();
        service().setReplyTimeout(ChronoUnit.FOREVER.getDuration());

        assertEquals(Optional.of(true), item().exists());
    }

    @Test
    void aTimeoutIsAtLeastAMillisecond() {
        MessageHandler handler = new MessageHandler(null);

        assertThrows(NullPointerException.class, () -> handler.setReplyTimeout(null));
        assertThrows(IllegalArgumentException.class, () -> handler.setReplyTimeout(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> handler.setReplyTimeout(Duration.ofSeconds(-1)));
        // getReply would wait 0 ms for it, which is without end.
        assertThrows(IllegalArgumentException.class, () -> handler.setReplyTimeout(Duration.ofNanos(999_999)));
        assertEquals(Static.DEFAULT_REPLY_TIMEOUT, handler.getReplyTimeout(), "a refused timeout changes nothing");

        handler.setReplyTimeout(Duration.ofMillis(1));
        assertEquals(Duration.ofMillis(1), handler.getReplyTimeout());
    }
}
