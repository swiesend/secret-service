package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Item;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A provider that is merely slow must not be reported as proof that an item exists.
 *
 * <p>{@code getReply} answers {@code null} after {@link Static.DBus#MAX_DELAY_MILLIS}. That null
 * is not an {@code Error}, so it used to fall through to the success branch: the value was empty,
 * which left {@code send()} looking correct, but the <em>outcome</em> said {@code OK}. And
 * {@code Item.exists()} switches on the outcome, so a two-second-slow keyring answered "yes, the
 * item is there".</p>
 *
 * <p>That is the fail-open the whole OK/ABSENT/UNAVAILABLE distinction exists to prevent, on the
 * commonest failure of all, and it made {@code UNAVAILABLE} unreachable for a timeout. A caller
 * that trusts {@code exists()} before overwriting or deleting would act on it.</p>
 */
class SlowProviderExistenceTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private FakeSecretService fake;

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        // Turn stalling off first: teardown reads properties too, and would otherwise pay the
        // stall on every call.
        if (fake != null) fake.setStallItemProperties(false);
        harness.stop();
    }

    @Test
    void aTimedOutProbeCannotTellWhetherTheItemExists() throws Exception {
        CollectionInterface collection = harness.start(false);
        fake = harness.fake();

        Item item = new Item(Static.Convert.toObjectPath(FakeSecretService.ITEM_PATH),
                harness.rawService());

        // Baseline: while the provider answers, the item is reported present. Without this the
        // test would pass against an exists() that always answered empty.
        assertEquals(Optional.of(true), item.exists(),
                "a responsive provider reports the item as present");

        fake.setStallItemProperties(true);

        long start = java.lang.System.nanoTime();
        Optional<Boolean> verdict = item.exists();
        long elapsedMs = (java.lang.System.nanoTime() - start) / 1_000_000L;

        assertTrue(elapsedMs >= Static.DBus.MAX_DELAY_MILLIS,
                "the probe should have waited for the timeout, but returned after " + elapsedMs + "ms");
        assertEquals(Optional.empty(), verdict,
                "a timeout means we cannot tell; reporting Optional.of(true) would let a caller "
                        + "overwrite or delete on the strength of a slow reply");
    }
}
