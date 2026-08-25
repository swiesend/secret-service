package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
    void failedPersistDoesNotLeaveAnUnpersistedEpochLiveInMemory() {
        // Regression: getOrCreate used to put the fresh keypair into `entries` and only then
        // persist. When persist failed, the entry survived in memory -- and because loadIfPresent
        // short-circuits (and finds nothing to reload when no keystore exists yet), the caller's
        // retry got the SAME keypair back without ever writing it. The item then sealed fine under
        // an epoch whose private key lived only in this JVM's heap: permanently undecryptable
        // after a restart. The retry must re-attempt the persist, not silently succeed.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);
        EpochKeystore ks = new EpochKeystore(fake, p);

        fake.setNextCreateItemFails(true);
        assertThrows(IllegalStateException.class, () -> ks.getOrCreate("e1", kem),
                "the first persist fails");
        assertEquals(0, ks.sizeForTest(),
                "the un-persisted epoch must be rolled back out of memory, not left live");
        assertEquals(0, keystoreItems(fake).size(), "nothing was written");

        // The retry must actually persist this time.
        ks.getOrCreate("e1", kem);
        assertEquals(1, keystoreItems(fake).size(),
                "the retry must durably write the keystore, not reuse an in-memory-only epoch");

        // Proof of the real-world consequence: a fresh reader (a restart) can load the epoch.
        assertTrue(new EpochKeystore(fake, p).get("e1").isPresent(),
                "after a restart the epoch key must still be recoverable");
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
    void failedMlKemImportPreservesTheKeyMaterialAndIsFullyRecoverable() {
        // A JVM without an ML-KEM provider used to DESTROY the PQ half: deserialize left mlkem null,
        // and serialize then wrote a zero-length private, so the next persist made the loss
        // permanent -- even after returning to a PQ-capable JVM. The bytes must survive untouched.
        HybridKem pqKem = new HybridKem(true);
        assumeTrue(pqKem.postQuantumAvailable(), "needs an ML-KEM provider to set up the fixture");

        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        new EpochKeystore(fake, p).getOrCreate("pq-epoch", pqKem);
        String blobBefore = fake.rawItems().get(keystoreItems(fake).get(0)).rawSecret();

        // Simulate the PQ-less JVM: every import fails, and then something persists.
        EpochKeystore.setMlKemImporterForTesting((priv, pub) -> {
            throw new IllegalStateException("ML-KEM provider unavailable; cannot import PQ keypair");
        });
        try {
            EpochKeystore degraded = new EpochKeystore(fake, p);
            assertTrue(degraded.get("pq-epoch").isPresent(), "the epoch still loads");
            degraded.getOrCreate("second-epoch", pqKem);   // forces a persist of the degraded state
        } finally {
            EpochKeystore.setMlKemImporterForTesting(null);
        }

        // Back on a PQ-capable JVM the original epoch must be whole again.
        EpochKeystore recovered = new EpochKeystore(fake, p);
        EpochKeystore.EpochKeyPair pair = recovered.get("pq-epoch").orElseThrow();
        assertNotNull(pair.mlkem, "the ML-KEM keypair must be importable again after the outage");
        assertNotNull(pair.mlkemPrivEncoded, "the private bytes must have survived the outage");
        assertTrue(pair.hasStoredPqHalf(), "both halves are still on disk");
        assertNotEquals(blobBefore, fake.rawItems().get(keystoreItems(fake).get(0)).rawSecret(),
                "sanity: the blob really was rewritten while the importer was failing");
    }

    @Test
    void upgradePqDoesNotMintOverAnEpochWhosePqHalfMerelyFailedToImport() {
        // upgradePqIfNeeded gated on `mlkem == null`, which is also true for an entry we simply
        // could not import -- so it minted a fresh pair and overwrote the surviving PUBLIC key,
        // orphaning every item sealed under the old one.
        HybridKem pqKem = new HybridKem(true);
        assumeTrue(pqKem.postQuantumAvailable(), "needs an ML-KEM provider to set up the fixture");

        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        new EpochKeystore(fake, p).getOrCreate("pq-epoch", pqKem);
        EpochKeystore.EpochKeyPair original = new EpochKeystore(fake, p).get("pq-epoch").orElseThrow();
        byte[] pubBefore = original.mlkemPubEncoded.clone();

        EpochKeystore.setMlKemImporterForTesting((priv, pub) -> {
            throw new IllegalStateException("ML-KEM provider unavailable; cannot import PQ keypair");
        });
        try {
            // getOrCreate on the existing epoch is the path that calls upgradePqIfNeeded.
            new EpochKeystore(fake, p).getOrCreate("pq-epoch", pqKem);
        } finally {
            EpochKeystore.setMlKemImporterForTesting(null);
        }

        EpochKeystore.EpochKeyPair after = new EpochKeystore(fake, p).get("pq-epoch").orElseThrow();
        assertArrayEquals(pubBefore, after.mlkemPubEncoded,
                "the surviving ML-KEM public key must not be replaced by a freshly minted one");
    }

    @Test
    void retainOnlyRefusesAnEpochItDoesNotHold() {
        // retainAll(Set.of(unknown)) empties the map, so this call would destroy EVERY epoch key
        // and persist an empty keystore -- making every item in the collection permanently
        // undecryptable. rotateEpoch used to reach exactly this state on an empty enumeration.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);
        EpochKeystore ks = new EpochKeystore(fake, p);
        ks.getOrCreate("e1", kem);

        assertThrows(IllegalStateException.class, () -> ks.retainOnly("never-created"),
                "retaining an unheld epoch must be refused, not silently empty the keystore");
        assertEquals(1, ks.sizeForTest(), "the held epoch must survive");
        assertTrue(new EpochKeystore(fake, p).get("e1").isPresent(),
                "and must still be loadable from a fresh instance");
    }

    @Test
    void equalGenerationKeystoresAreBothPreserved() {
        // Two writers over one collection can persist at the same generation. The winner used to be
        // decided by daemon-returned item order and the loser hard-deleted -- destroying that
        // writer's epoch keys. Only a STRICTLY lower generation is provably superseded.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        new EpochKeystore(fake, p).getOrCreate("e1", kem);
        String path = keystoreItems(fake).get(0);
        FakeCollection.Item snapshot = fake.rawItems().get(path);
        // A peer writer's snapshot at the SAME generation.
        fake.seedRaw("/epoch-keystore/peer", EpochKeystore.LABEL,
                snapshot.rawSecret(), Map.copyOf(snapshot.attrs()));
        assertEquals(2, keystoreItems(fake).size());

        new EpochKeystore(fake, p).get("e1"); // triggers a load + duplicate resolution
        assertEquals(2, keystoreItems(fake).size(),
                "an equal-generation peer snapshot must not be deleted");
    }

    @Test
    void rollbackRefusalIsStickyAndDoesNotOrphanTheKeystore() {
        // The refusal left keystorePath == null, so the next persist created a SECOND keystore at
        // floor+1 and deleted nothing -- and the following load then picked that (empty) one as
        // highest and destroyed the genuine snapshot. A refusal must not become the destruction it
        // was meant to prevent.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);
        FakeAnchor anchor = new FakeAnchor();

        EpochKeystore writer = new EpochKeystore(fake, p, anchor);
        writer.getOrCreate("e1", kem);
        writer.getOrCreate("e2", kem);          // generation 2, anchor 2
        String genOnePath = keystoreItems(fake).get(0);
        FakeCollection.Item current = fake.rawItems().get(genOnePath);

        // Roll the store back below the floor: re-seed an older snapshot as the only keystore.
        fake.deleteItem(genOnePath);
        fake.seedRaw("/rollback/old", EpochKeystore.LABEL, current.rawSecret(), Map.copyOf(current.attrs()));
        anchor.value = 99L;                     // floor far above anything present

        EpochKeystore refusedKs = new EpochKeystore(fake, p, anchor);
        assertTrue(refusedKs.get("e1").isEmpty(), "a below-floor keystore is refused");
        assertThrows(IllegalStateException.class, () -> refusedKs.getOrCreate("e3", kem),
                "a refused keystore must refuse writes rather than fork a second keystore");
        assertEquals(1, keystoreItems(fake).size(),
                "no second keystore item may be created after a refusal");
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
        boolean throwOnRead;    // models an anchor I/O error (e.g. TPM unreachable) on read
        boolean throwOnAdvance; // ... on advance
        FakeAnchor() {}
        FakeAnchor(long start) { this.value = start; }
        @Override public long read() {
            if (throwOnRead) throw new IllegalStateException("anchor read failed (simulated TPM error)");
            return value;
        }
        @Override public long advanceTo(long target) {
            if (throwOnAdvance) throw new IllegalStateException("anchor advance failed (simulated TPM error)");
            if (target > value) value = target;
            return value;
        }
        @Override public void close() { closed = true; }
        /** Test hook: rewind the counter to model a crash between write and advance. */
        void rewindTo(long v) { this.value = v; }
    }

    @Test
    void anchorReadErrorFailsLoudNotAsSilentRollback() {
        // The DoS-vs-rollback distinction (GenerationAnchor contract): a below-floor keystore is
        // refused gracefully (get() returns empty, see anchorRefusesRolledBackKeystore), but an
        // anchor whose read() THROWS is a hard failure -- the keystore must NOT silently proceed as
        // if there were no anchor. It fails loudly so a broken anti-rollback anchor cannot be
        // bypassed; at the HardenedCollection layer this surfaces as a fail-safe empty read.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        new EpochKeystore(fake, p, new FakeAnchor()).getOrCreate("e1", kem); // persist a keystore

        FakeAnchor broken = new FakeAnchor();
        broken.throwOnRead = true;
        EpochKeystore reader = new EpochKeystore(fake, p, broken);
        assertThrows(RuntimeException.class, () -> reader.get("e1"),
                "an anchor I/O error must fail loudly, not be silently ignored (rollback protection intact)");
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

    @Test
    void persistDoesNotZeroTheStoredMlKemPrivateKey() {
        // NOT a regression test: this passes against the pre-fix code too, because the defect it
        // relates to -- serialize()'s sizing loop leaving a private key as heap garbage -- is not
        // observable through any API. Erasure can only be shown by inspecting the heap.
        //
        // What this DOES pin is the hazard the fix introduces: serialize() now encodes each private
        // key once and erases that copy in a finally, so the copy must be exactly that. Erasing the
        // LIVE mlkemPrivEncoded field instead would destroy the in-memory epoch, and the damage
        // would surface only on a later persist. Hence two persists and a reload.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(true);   // PQ on, so there IS an ML-KEM half to erase

        EpochKeystore ks = new EpochKeystore(fake, p);
        ks.getOrCreate("e1", kem);
        ks.getOrCreate("e2", kem);   // a SECOND persist re-serializes e1's key material

        EpochKeystore reloaded = new EpochKeystore(fake, p);
        assertTrue(reloaded.get("e1").isPresent(),
                "e1 must survive being serialized twice; a zeroed live key would not round-trip");
        assertTrue(reloaded.get("e2").isPresent());
    }

    @Test
    void aFailedSearchForTheKeystoreFailsClosedRatherThanForkingASecondOne() {
        // loadIfPresent treated Optional.empty() -- the SEARCH FAILED -- as "there is no keystore".
        // A transient failure therefore left keystorePath null, so the next persist did not replace
        // the real keystore but JOINED it at generation 1. The following load picks the genuine one
        // (higher generation) and deletes ours as superseded, taking with it the only copy of the
        // keys for everything written during the degraded session. Fail closed instead.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        EpochKeystore writer = new EpochKeystore(fake, p);
        writer.getOrCreate("e1", kem);
        assertEquals(1, keystoreItems(fake).size());

        EpochKeystore degraded = new EpochKeystore(fake, p);
        fake.setNextGetItemsFails(true);
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> degraded.getOrCreate("e2", kem),
                "a keystore whose enumeration failed must refuse to write, not mint a rival");
        assertTrue(e.getMessage().contains("enumeration failed"), e.getMessage());

        assertEquals(1, keystoreItems(fake).size(),
                "no second keystore may be forked while the real one is merely unreadable");
    }

    @Test
    void aFailedPersistDuringRetainOnlyRollsTheEntriesBack() {
        // retainAll ran BEFORE persist, so a transient write failure destroyed the superseded keys
        // IN MEMORY while the on-disk keystore still held them: every item under an old epoch
        // became unreadable for the rest of the process lifetime. rotateEpoch's contract says a
        // false return means "the old keys are still usable" -- which this made a lie. Every other
        // mutator here rolls back on a failed persist; retainOnly was the one that did not.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        EpochKeystore ks = new EpochKeystore(fake, p);
        ks.getOrCreate("e-old", kem);
        ks.getOrCreate("e-new", kem);

        fake.setNextCreateItemFails(true); // the retainOnly persist will fail
        assertThrows(IllegalStateException.class, () -> ks.retainOnly("e-new"));

        assertTrue(ks.get("e-old").isPresent(),
                "a failed persist must leave the superseded epoch keys usable in memory");
        assertTrue(ks.get("e-new").isPresent());

        // And the destruction still works once the transient clears.
        ks.retainOnly("e-new");
        assertTrue(ks.get("e-old").isEmpty(), "the retry destroys the superseded epoch");
        assertTrue(ks.get("e-new").isPresent());
    }

    @Test
    void keystoreIsFoundEvenWhenTheFilteredSearchLies() {
        // The keystore was located with a filtered SearchItems query -- the exact mechanism this
        // project documents as provider-unreliable and that rewrapCovered refuses to trust. A
        // filtered search that returns SUCCESSFULLY EMPTY while the keystore item exists landed on
        // "genuinely no keystore yet", and the next persist forked a second keystore at
        // generation 1 -- whereupon the next load deleted it as superseded, destroying that
        // session's epoch keys. Locating via the full enumeration (Items property) plus a local
        // attribute filter is immune to the lie.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        EpochKeystore writer = new EpochKeystore(fake, p);
        writer.getOrCreate("e1", kem);
        assertEquals(1, keystoreItems(fake).size());

        fake.setFilteredGetItemsLies(true); // SearchItems-style queries now return empty
        EpochKeystore reader = new EpochKeystore(fake, p);
        assertTrue(reader.get("e1").isPresent(),
                "the keystore must be found through the honest full enumeration");
        reader.getOrCreate("e2", kem); // a write must UPDATE the keystore, not fork a rival

        fake.setFilteredGetItemsLies(false);
        assertEquals(1, keystoreItems(fake).size(),
                "exactly one keystore item: found and replaced, never forked");
    }

    @Test
    void aForeignItemDeletedMidLoadIsSkippedRatherThanBrickingTheKeystore() {
        // Locating the keystore reads every item's attributes. An item another application deletes
        // between the enumeration and that read is routine on a shared collection -- and refusing
        // service for it would make the hardened layer unusable exactly where it is meant to run.
        // itemExists distinguishes "provably gone" (skip) from "cannot read it" (fail closed).
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        EpochKeystore writer = new EpochKeystore(fake, p);
        writer.getOrCreate("e1", kem);

        // A path the enumeration reports but that no longer resolves: gone, not unreadable.
        fake.seedPlain("/foreign/ghost", "ghost", "gone-in-a-moment", Map.of());
        fake.deleteItem("/foreign/ghost");
        fake.setPhantomPath("/foreign/ghost");

        EpochKeystore reader = new EpochKeystore(fake, p);
        assertTrue(reader.get("e1").isPresent(),
                "a vanished foreign item must not stop the keystore being found");
    }

    @Test
    void anUnreadableButPresentItemFailsClosed() {
        // The other half of the same distinction: an item that is still there but whose attributes
        // we cannot read MIGHT be the keystore, so proceeding would risk forking a second one.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        EpochKeystore writer = new EpochKeystore(fake, p);
        writer.getOrCreate("e1", kem);
        fake.seedPlain("/foreign/locked", "locked", "cannot-read-me", Map.of());
        fake.setUnreadable("/foreign/locked");

        EpochKeystore reader = new EpochKeystore(fake, p);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> reader.get("e1"));
        assertTrue(e.getMessage().contains("could not establish that the item is gone"), e.getMessage());
        assertEquals(1, keystoreItems(fake).size(), "and no rival keystore was forked");
    }

    @Test
    void aFailedReadOfTheKeystoreBodyDoesNotLookLikeAnAbsentKeystore() {
        // The third read in loadIfPresent -- the candidate's BODY -- collapsed "we judged this and
        // it is not ours" with "we never read it" via .orElse(null). A failed read of the genuine
        // keystore therefore left best == null, and the next persist forked a rival at generation 1
        // whose deletion on the following load destroys this session's epoch keys.
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider p = provider("a-test-pepper-long-enough-for-derivation");
        HybridKem kem = new HybridKem(false);

        EpochKeystore writer = new EpochKeystore(fake, p);
        writer.getOrCreate("e1", kem);
        String keystorePath = keystoreItems(fake).get(0);

        // Attributes still classify it as a keystore candidate; only the BODY fails, so this
        // reaches the third guard rather than tripping the attribute guard above it.
        fake.setBodyUnreadable(keystorePath);

        EpochKeystore reader = new EpochKeystore(fake, p);
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> reader.getOrCreate("e2", kem),
                "a keystore whose body could not be read must not be treated as absent");
        assertTrue(e.getMessage().contains("could not read the body of keystore candidate"),
                e.getMessage());
        assertEquals(1, keystoreItems(fake).size(),
                "no rival keystore may be forked beside the one we merely failed to read");
    }
}
