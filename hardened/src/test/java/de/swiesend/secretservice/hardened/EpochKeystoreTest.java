package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link EpochKeystore}'s persistence and load logic -- specifically the
 * create-then-delete durability guarantee (Fix #2) and the generation-based selection when
 * more than one keystore item is present after an interrupted persist.
 */
class EpochKeystoreTest {

    /** Minimal fixed-pepper provider; the keystore only uses getPepper(). */
    private static KeyMaterialProvider provider(String pepper) {
        return new KeyMaterialProvider() {
            @Override public char[] getPepper() { return pepper.toCharArray(); }
            @Override public ThreatCoverage threatCoverage() {
                return new ThreatCoverage(
                        ThreatCoverage.Level.PARTIAL, ThreatCoverage.Level.REAL,
                        ThreatCoverage.Level.REAL, ThreatCoverage.Level.NOT_APPLICABLE,
                        "test provider");
            }
        };
    }

    private static List<String> keystoreItems(FakeCollection fake) {
        return fake.getItems(Map.of(EpochKeystore.ATTR_KIND, EpochKeystore.KIND_VALUE))
                .orElseThrow();
    }

    @Test
    void persistFailureLeavesOldKeystoreIntactAndLoadable() {
        // Create-then-delete durability: if createItem fails mid-persist, the previously
        // persisted keystore item must survive so the epoch private keys are not lost.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        EpochKeystore ks = new EpochKeystore(fake, p);
        ks.getOrCreate("epoch-1", kem); // first persist writes the keystore item (generation 1)
        assertEquals(1, keystoreItems(fake).size(), "one keystore item after first persist");

        // The next persist (triggered by adding epoch-2) will call createItem, which fails.
        fake.setNextCreateItemFails(true);
        assertThrows(IllegalStateException.class, () -> ks.getOrCreate("epoch-2", kem),
                "persist must throw when createItem returns empty");

        // The original keystore item (epoch-1, generation 1) must still be present and loadable.
        assertEquals(1, keystoreItems(fake).size(),
                "old keystore item must survive a failed persist -- no data loss");

        EpochKeystore reloaded = new EpochKeystore(fake, p);
        assertTrue(reloaded.get("epoch-1").isPresent(),
                "epoch-1 keys must still load after the failed persist");
        assertTrue(reloaded.get("epoch-2").isEmpty(),
                "epoch-2 was never durably written; it must not appear on reload");
    }

    @Test
    void loadPicksHighestGenerationAndRemovesSupersededDuplicate() {
        // Simulate an interrupted create-then-delete: an older keystore item (generation 1)
        // lingers next to the newer one (generation 2). Load must pick the highest generation
        // (so no epoch key is resurrected or stranded) and delete the provably-superseded copy.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        EpochKeystore writer = new EpochKeystore(fake, p);
        writer.getOrCreate("epoch-1", kem); // generation 1: {epoch-1}
        // Capture the generation-1 body before it is superseded.
        String genOnePath = keystoreItems(fake).get(0);
        FakeCollection.Item genOne = fake.rawItems().get(genOnePath);
        String genOneBody = genOne.rawSecret();
        Map<String, String> genOneAttrs = Map.copyOf(genOne.attrs());

        writer.getOrCreate("epoch-2", kem); // generation 2: {epoch-1, epoch-2}; deletes gen-1 item
        assertEquals(1, keystoreItems(fake).size(), "create-then-delete leaves exactly one item");

        // Re-seed the stale generation-1 body at a fresh path to mimic a crash before the delete.
        fake.seedRaw("/epoch-keystore/stale-gen1", EpochKeystore.LABEL, genOneBody, genOneAttrs);
        assertEquals(2, keystoreItems(fake).size(), "two keystore items now present");

        EpochKeystore reader = new EpochKeystore(fake, p);
        // Highest generation (2) wins: both epochs are present.
        assertTrue(reader.get("epoch-1").isPresent());
        assertTrue(reader.get("epoch-2").isPresent(),
                "the generation-2 snapshot (both epochs) must win over the stale generation-1 copy");
        // The superseded duplicate must have been removed during load.
        assertEquals(1, keystoreItems(fake).size(),
                "the provably-superseded generation-1 duplicate must be deleted on load");
        assertFalse(fake.rawItems().containsKey("/epoch-keystore/stale-gen1"),
                "the stale generation-1 item specifically must be the one removed");
    }

    @Test
    void undecryptableForeignKeystoreIsLeftUntouched() {
        // A keystore item written under a different pepper cannot be decrypted by us. It must
        // neither crash the load nor be deleted -- we only remove copies we can prove are ours.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider ours = provider("our-own-pepper-long-enough-xyz");
        HybridKem kem = new HybridKem(false);

        EpochKeystore writer = new EpochKeystore(fake, ours);
        writer.getOrCreate("epoch-1", kem);

        // Seed a foreign keystore written under a different pepper.
        FakeCollection other = new FakeCollection();
        new EpochKeystore(other, provider("a-completely-different-pepper-abc"))
                .getOrCreate("foreign-epoch", kem);
        String foreignPath = other.getItems(Map.of(EpochKeystore.ATTR_KIND, EpochKeystore.KIND_VALUE))
                .orElseThrow().get(0);
        FakeCollection.Item foreign = other.rawItems().get(foreignPath);
        fake.seedRaw("/epoch-keystore/foreign", EpochKeystore.LABEL,
                foreign.rawSecret(), Map.copyOf(foreign.attrs()));

        EpochKeystore reader = new EpochKeystore(fake, ours);
        assertTrue(reader.get("epoch-1").isPresent(), "our keystore must still load");
        assertTrue(reader.get("foreign-epoch").isEmpty(), "the foreign epoch must not be visible");
        // The undecryptable foreign item must be left in place, not deleted.
        assertTrue(fake.rawItems().containsKey("/epoch-keystore/foreign"),
                "an undecryptable foreign keystore must be left untouched");
    }

    // ---------- anti-rollback anchor (GenerationAnchor) ----------

    /** In-memory monotonic anchor standing in for a TPM NV counter. */
    static final class FakeAnchor implements GenerationAnchor {
        long value;
        boolean closed;
        FakeAnchor() {}
        FakeAnchor(long start) { this.value = start; }
        @Override public long read() { return value; }
        @Override public long advanceTo(long target) { if (target > value) value = target; return value; }
        @Override public void close() { closed = true; }
        /** Test hook: rewind the counter to model a crash between write and advance. */
        void rewindTo(long v) { this.value = v; }
    }

    @Test
    void generationLivesInTheAnchorValueSpace() {
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);
        FakeAnchor anchor = new FakeAnchor(1000L); // TPM counters can start at a large value

        EpochKeystore ks = new EpochKeystore(fake, p, anchor);
        ks.getOrCreate("e1", kem);
        assertEquals(1001L, anchor.read(), "first persist seeds the generation from the anchor floor + 1");
        ks.getOrCreate("e2", kem);
        assertEquals(1002L, anchor.read(), "each persist advances the anchor by one");
    }

    @Test
    void anchorRefusesRolledBackKeystore() {
        // Window-0 anti-rollback: an attacker who re-introduces a genuine older snapshot while the
        // anchor stays high must be refused -- highest-of-what's-present is not enough.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);
        FakeAnchor anchor = new FakeAnchor();

        EpochKeystore writer = new EpochKeystore(fake, p, anchor);
        writer.getOrCreate("e1", kem); // generation 1
        String genOnePath = keystoreItems(fake).get(0);
        FakeCollection.Item genOne = fake.rawItems().get(genOnePath);
        String genOneBody = genOne.rawSecret();
        Map<String, String> genOneAttrs = Map.copyOf(genOne.attrs());

        writer.getOrCreate("e2", kem); // generation 2; anchor now 2; gen-1 item deleted
        assertEquals(2L, anchor.read());

        // Attacker rolls back: drop the current (gen-2) item, re-introduce the captured gen-1 one.
        fake.deleteItem(keystoreItems(fake).get(0));
        fake.seedRaw("/rollback/gen1", EpochKeystore.LABEL, genOneBody, genOneAttrs);

        EpochKeystore reader = new EpochKeystore(fake, p, anchor);
        assertTrue(reader.get("e1").isEmpty(),
                "a below-floor (rolled-back) keystore must be refused, not loaded");
        assertTrue(reader.get("e2").isEmpty());
        assertEquals(0, reader.sizeForTest(), "nothing is loaded on a refused rollback (fail-closed)");
    }

    @Test
    void anchorCatchesUpWhenKeystoreGenerationExceedsFloor() {
        // Crash between the durable write and the anchor advance leaves generation > floor. That is
        // a lost-advance, not a rollback: the snapshot must load and the anchor must catch up.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);
        FakeAnchor anchor = new FakeAnchor();

        EpochKeystore writer = new EpochKeystore(fake, p, anchor);
        writer.getOrCreate("e1", kem);
        writer.getOrCreate("e2", kem); // generation 2, anchor 2
        anchor.rewindTo(1L);           // model a crash before the last advance landed

        EpochKeystore reader = new EpochKeystore(fake, p, anchor);
        assertTrue(reader.get("e1").isPresent());
        assertTrue(reader.get("e2").isPresent(),
                "generation 2 > floor 1 is a lost-advance and must still load");
        assertEquals(2L, anchor.read(), "the anchor is caught up to the loaded generation");
    }
}
