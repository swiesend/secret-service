package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.Collection;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code itemExists} scoping must not break the default collection.
 *
 * <p>{@code openDefault()} addresses the collection as
 * {@code /org/freedesktop/secrets/aliases/default} while its items live under the canonical
 * {@code /org/freedesktop/secrets/collection/<id>/}. A first version of the scope check compared
 * item paths against the collection's own path -- the alias -- so every item the default
 * collection actually holds was answered {@code of(false)}: "provably absent", deterministically,
 * without asking the daemon. That is the one answer that licenses a caller's destructive
 * recreate-or-overwrite branch, for items that exist.</p>
 *
 * <p>Runs against the in-process fake on a private bus -- {@code openDefault} here never touches
 * the machine's real default keyring.</p>
 */
class DefaultCollectionScopingTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private FakeSecretService fake;

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    @Test
    void anAliasAddressedCollectionStillSeesItsOwnItems() throws Exception {
        harness.start(false);
        fake = harness.fake();

        // The alias-addressed route openDefault() takes; the fake serves the same collection at
        // the alias path, as gnome-keyring does.
        CollectionInterface byAlias = Collection.openDefault(Optional.of(harness.session()))
                .orElseThrow(() -> new IllegalStateException("could not open the aliased collection"));

        assertEquals(Optional.of(true), byAlias.itemExists(FakeSecretService.ITEM_PATH),
                "an existing item of the default collection must not be reported 'provably absent' "
                        + "just because the collection is addressed through its alias");

        // For alias addressing the scoping question stays daemon-answered. What matters is that
        // a nonexistent path is never reported PRESENT; whether it comes back of(false) or empty
        // depends on the daemon's error wording -- gnome-keyring's "does not exist at path" text
        // narrows to ABSENT, while this fake's bus library words it differently and correctly
        // stays fail-closed at empty.
        assertEquals(Optional.empty(),
                byAlias.itemExists(FakeSecretService.COLLECTION_PATH + "/999999")
                        .filter(present -> present),
                "a path with no object behind it must never be reported present");

        // The ACTING methods must stay usable through the alias too: scoping is judged only for
        // canonically-addressed collections, so an alias-opened default collection can still read
        // its own items. Without that carve-out, widening the scope to the acting methods would
        // have re-shipped the itemExists alias regression across the whole read/write surface.
        assertEquals(Optional.of("fake-item"), byAlias.getItemLabel(FakeSecretService.ITEM_PATH),
                "an alias-addressed collection still reads its own item's label");
    }
}
