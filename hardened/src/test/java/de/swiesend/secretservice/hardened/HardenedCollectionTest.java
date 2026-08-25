package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HardenedCollectionTest {

    private FakeCollection fake;
    private KeyMaterialProvider provider;

    @BeforeEach
    void setUp() {
        fake = new FakeCollection();
        String pepper = "a-test-pepper-that-is-reasonably-long-for-derivation";
        provider = new EnvVarKeyMaterialProvider(pepper);
    }

    private HardenedCollection build() {
        return HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .build();
    }

    @Test
    void builderRequiresKeyMaterialAtCompileTime() {
        // The provider is now a required factory argument; null must be rejected.
        assertThrows(NullPointerException.class,
                () -> HardenedCollection.builder(fake, null));
        assertThrows(NullPointerException.class,
                () -> HardenedCollection.builder(null, provider));
    }

    @Test
    void refusesWeakProviderWithoutAcknowledgement() {
        HardenedCollection.Builder b = HardenedCollection.builder(fake, provider);
        SameUidExposureException e = assertThrows(SameUidExposureException.class, b::build);
        assertTrue(e.getMessage().contains("theater") || e.getMessage().contains("NONE"));
    }

    @Test
    void sameUidExposureMustBeAcknowledgedAndTheMessageExplainsWhy() {
        // The gate fires on exactly one condition: the provider reports sameUid=NONE. The message
        // is the only thing a blocked caller sees, so it must say what is lost, what still holds,
        // and what to do about it -- not just name the flag.
        SameUidExposureException e = assertThrows(SameUidExposureException.class,
                () -> HardenedCollection.builder(fake, provider).build());
        String m = e.getMessage();
        assertTrue(m.contains("sameUid=NONE"), m);
        assertTrue(m.contains("What this means"), "explains the loss: " + m);
        assertTrue(m.contains("What still holds"), "explains what is unaffected: " + m);
        assertTrue(m.contains("Tpm2KeyMaterialProvider"), "names the production alternative: " + m);
        assertTrue(m.contains("acknowledgeSameUidExposure(true)"), "names the escape hatch: " + m);

        // A PARTIAL/REAL provider needs no acknowledgement at all.
        assertNotNull(HardenedCollection.builder(fake, providerWithSameUid(ThreatCoverage.Level.PARTIAL))
                .build());
    }

    @Test
    void suppressingTheWarningDoesNotSuppressTheGate() {
        // The suppression flag is log hygiene only: on its own it must not let an unacknowledged
        // provider through.
        assertThrows(SameUidExposureException.class,
                () -> HardenedCollection.builder(fake, provider)
                        .suppressSameUidExposureWarning(true)
                        .build(),
                "suppressing the warning must not imply acknowledging the exposure");

        assertNotNull(HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .suppressSameUidExposureWarning(true)
                .build(),
                "with the exposure acknowledged, the flag only silences the WARN");
    }

    private KeyMaterialProvider providerWithSameUid(ThreatCoverage.Level level) {
        return new KeyMaterialProvider() {
            @Override public char[] getPepper() { return "a-pepper-long-enough-for-derivation".toCharArray(); }
            @Override public ThreatCoverage threatCoverage() {
                return new ThreatCoverage(level, ThreatCoverage.Level.REAL, ThreatCoverage.Level.REAL,
                        ThreatCoverage.Level.NOT_APPLICABLE, "test provider");
            }
        };
    }

    @Test
    void createAndReadRoundTrip() {
        HardenedCollection h = build();
        Optional<String> path = h.createItem("my-label", "s3cr3t-password");
        assertTrue(path.isPresent());

        Optional<String> fetched = h.withSecret(path.get(), chars -> new String(chars));
        assertEquals("s3cr3t-password", fetched.orElse(null));
    }

    /** A provider that records whether close() was called on it. */
    private static KeyMaterialProvider closeTracking(java.util.concurrent.atomic.AtomicBoolean flag) {
        return new KeyMaterialProvider() {
            @Override public char[] getPepper() { return "p3pper-of-decent-length-yo!".toCharArray(); }
            @Override public ThreatCoverage threatCoverage() {
                return new ThreatCoverage(
                        ThreatCoverage.Level.PARTIAL, ThreatCoverage.Level.REAL,
                        ThreatCoverage.Level.REAL, ThreatCoverage.Level.NOT_APPLICABLE,
                        "test provider with close-tracking");
            }
            @Override public void close() { flag.set(true); }
        };
    }

    @Test
    void closeDoesNotTouchCallerSuppliedProviderOrCollectionByDefault() {
        // You close what you constructed. close() used to close the caller's provider AND the
        // wrapped collection -- the latter tears down the D-Bus session, silently breaking any
        // other code sharing that connection, and a provider shared between two collections is
        // left unusable by whichever closes first. Neither object is ours, so we close neither.
        java.util.concurrent.atomic.AtomicBoolean providerClosed = new java.util.concurrent.atomic.AtomicBoolean(false);
        KeyMaterialProvider counting = closeTracking(providerClosed);

        try (HardenedCollection h = HardenedCollection.builder(fake, counting).build()) {
            h.createItem("x", "secret").orElseThrow();
        }
        assertFalse(providerClosed.get(),
                "close() must not close a caller-supplied provider by default");
        assertFalse(fake.isClosed(),
                "close() must not close the caller-supplied collection by default");

        // ... and the caller's objects are still usable afterwards.
        try (HardenedCollection h2 = HardenedCollection.builder(fake, counting).build()) {
            assertTrue(h2.createItem("y", "another").isPresent(),
                    "the shared provider and collection must survive the first close()");
        }
    }

    @Test
    void ownershipFlagsOptBackIntoClosing() {
        java.util.concurrent.atomic.AtomicBoolean providerClosed = new java.util.concurrent.atomic.AtomicBoolean(false);
        KeyMaterialProvider counting = closeTracking(providerClosed);

        try (HardenedCollection h = HardenedCollection.builder(fake, counting)
                .ownsProvider(true)
                .ownsWrapped(true)
                .build()) {
            h.createItem("x", "secret").orElseThrow();
        }
        assertTrue(providerClosed.get(), "ownsProvider(true) must restore closing the provider");
        assertTrue(fake.isClosed(), "ownsWrapped(true) must restore closing the wrapped collection");
    }

    @Test
    void closedProviderYieldsEmptyOptionalNotAnException() {
        // getPepper() used to be called OUTSIDE the guarding try in both createItem and the read
        // path, so a closed provider threw IllegalStateException straight through an API whose
        // whole contract is to return Optional.
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .build();
        String path = h.createItem("x", "value").orElseThrow();
        provider.close();

        assertTrue(h.createItem("y", "another").isEmpty(),
                "a closed provider must make createItem return empty, not throw");
        assertTrue(h.withSecret(path, String::new).isEmpty(),
                "a closed provider must make withSecret return empty, not throw");
        assertTrue(h.matchesSecret(path, "value".toCharArray()).isEmpty(),
                "a closed provider must make matchesSecret return empty, not throw");
    }

    @Test
    void defaultBuilderWritesKemIdX25519() {
        // The KEM is always on. Without enablePostQuantum(true), envelopes carry the classical
        // kem_id=KEM_ID_X25519 (0x03) with a non-empty kem_ct and no PQ-hybrid flag. This is what
        // gives epoch rotation forward secrecy even without a PQ component.
        HardenedCollection h = build();
        String path = h.createItem("x", "secret").orElseThrow();
        FakeCollection.Item stored = fake.rawItems().get(path);
        byte[] envBytes = Base64.getDecoder().decode(stored.rawSecret());
        Envelope env = Envelope.fromBytes(envBytes);
        assertEquals(Envelope.KEM_ID_X25519, env.kemId());
        assertTrue(env.kemCiphertext().length > 0, "classical KEM must carry an X25519 ephemeral SPKI");
        assertFalse(env.hasFlag(Envelope.FLAG_PQ_HYBRID), "classical envelopes must not set the PQ flag");
        assertEquals("0x03", stored.attrs().get(HardenedCollection.ATTR_KEM_ID));
        assertEquals("x25519", stored.attrs().get(HardenedCollection.ATTR_KEM));
        // Round-trips through the in-collection keystore.
        assertEquals("secret", h.withSecret(path, String::new).orElse(null));
    }

    @Test
    void tamperingWithEnvelopeHeaderFailsAuthentication() {
        // The AEAD associated data now covers the full envelope header, so flipping a header field
        // (here the flags byte at offset 5) must fail decryption rather than being silently accepted.
        HardenedCollection h = build();
        String path = h.createItem("x", "secret").orElseThrow();
        assertEquals("secret", h.withSecret(path, String::new).orElse(null), "sanity: reads before tamper");

        byte[] envBytes = Base64.getDecoder().decode(fake.rawItems().get(path).rawSecret());
        envBytes[5] = Envelope.FLAG_PQ_HYBRID; // flip the flags byte (was 0); still parses, but AAD changes
        fake.overwriteRawSecret(path, Base64.getEncoder().encodeToString(envBytes));

        assertTrue(h.withSecret(path, String::new).isEmpty(),
                "a tampered header must fail AEAD authentication and yield empty, not plaintext");
    }

    @Test
    void legacyV1AndV2EnvelopesAreRejectedGracefully() {
        // Formats v1/v2 (pre-suite-selector) are no longer supported. A stale legacy item must be
        // rejected gracefully -- withSecret returns empty rather than throwing -- so a leftover
        // alpha item never crashes a read.
        HardenedCollection h = build();
        for (byte legacy : new byte[]{Envelope.VERSION_1, Envelope.VERSION_2}) {
            byte[] env = new Envelope(Envelope.VERSION_3, (byte) 0, Envelope.AEAD_ID_AES256_GCM,
                    Envelope.KDF_ID_HKDF_SHA256, Envelope.KEM_ID_NONE, new byte[Envelope.SALT_LEN],
                    "legacy-epoch".getBytes(), "legacy-id".getBytes(),
                    new byte[0], new byte[Envelope.NONCE_LEN], new byte[32]).toBytes();
            env[4] = legacy; // downgrade the version byte -> an unsupported legacy envelope
            Map<String, String> attrs = new HashMap<>();
            attrs.put(HardenedCollection.ATTR_VERSION, HardenedCollection.ATTR_VERSION_V1);
            String path = "/legacy/v" + legacy;
            fake.seedRaw(path, "legacy", Base64.getEncoder().encodeToString(env), attrs);
            assertTrue(h.withSecret(path, String::new).isEmpty());
        }
    }

    @Test
    void postQuantumRoundTripWritesKemCtAndRecoversPlaintext() {
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .enablePostQuantum(true)
                .build();

        // Write an item via the PQ path.
        String path = h.createItem("pq-item", "h@rd3ned-PQ-secret").orElseThrow();

        // Inspect the envelope: kem_id should be KEM_ID_X25519_MLKEM768 and kem_ct must be non-empty.
        FakeCollection.Item stored = fake.rawItems().get(path);
        byte[] envBytes = Base64.getDecoder().decode(stored.rawSecret());
        Envelope env = Envelope.fromBytes(envBytes);
        assertEquals(Envelope.KEM_ID_X25519_MLKEM768, env.kemId(),
                "PQ envelopes must carry kem_id=KEM_ID_X25519_MLKEM768");
        assertTrue(env.kemCiphertext().length > 1000,
                "PQ kem_ct must include the ML-KEM-768 ciphertext (1088 bytes) plus the X25519 SPKI");
        assertTrue(env.hasFlag(Envelope.FLAG_PQ_HYBRID));

        // The item must round-trip via the same HardenedCollection (uses the in-collection keystore).
        String recovered = h.withSecret(path, String::new).orElseThrow();
        assertEquals("h@rd3ned-PQ-secret", recovered);
    }

    @Test
    void generationAnchorWiredThroughBuilderIsConsultedAndFailsClosed() {
        // Builder wiring smoke test: an anchored collection round-trips and the write advances the
        // anchor through the keystore. Then, with the anchor floor pushed above the stored keystore
        // generation (the condition a rollback creates -- the faithful attacker model is covered in
        // EpochKeystoreTest#anchorRefusesRolledBackKeystore), a fresh instance fails closed.
        EpochKeystoreTest.FakeAnchor anchor = new EpochKeystoreTest.FakeAnchor();
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true).epochId("anchored").generationAnchor(anchor).build();
        String path = h.createItem("x", "anchored-secret").orElseThrow();
        assertEquals("anchored-secret", h.withSecret(path, String::new).orElse(null));
        assertTrue(anchor.read() > 0, "the write must have advanced the anchor through the keystore");

        // Raise the floor above the stored keystore generation (equivalent to a rolled-back store).
        anchor.advanceTo(anchor.read() + 5);
        HardenedCollection h2 = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true).epochId("anchored").generationAnchor(anchor).build();
        assertTrue(h2.withSecret(path, String::new).isEmpty(),
                "with the anchor floor above the stored generation, KEM-wrapped reads fail closed");
    }

    @Test
    void writeUnderEpochLoadedFromKeystoreAcrossSessions() {
        // Two HardenedCollection instances over the same collection, reusing one epoch id, model
        // two process lifetimes. Session 2 loads the epoch from the keystore and must be able to
        // BOTH read the old item AND write a new one under that epoch. This regressed when the KEM
        // became always-on: a keystore-loaded epoch carried a null X25519 public, so encapsulation
        // (write) threw "missing its X25519 public key". Storing the public (keystore v2) fixes it.
        HardenedCollection s1 = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true).epochId("shared-epoch").build();
        String p1 = s1.createItem("a", "secret-a").orElseThrow();

        HardenedCollection s2 = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true).epochId("shared-epoch").build();
        assertEquals("secret-a", s2.withSecret(p1, String::new).orElse(null),
                "session 2 must read the item written by session 1");
        String p2 = s2.createItem("b", "secret-b").orElseThrow(); // previously threw / returned empty
        assertEquals("secret-b", s2.withSecret(p2, String::new).orElse(null),
                "session 2 must read the item it wrote under the loaded epoch");
        assertEquals("secret-b", s1.withSecret(p2, String::new).orElse(null),
                "the item written by session 2 must be readable through session 1 too");
    }

    @Test
    void emittedSecretIsBase64EnvelopeNotPlaintext() {
        HardenedCollection h = build();
        String path = h.createItem("x", "plaintext-value").orElseThrow();
        FakeCollection.Item stored = fake.rawItems().get(path);
        assertNotNull(stored);
        assertNotEquals("plaintext-value", stored.rawSecret());
        byte[] decoded = Base64.getDecoder().decode(stored.rawSecret());
        assertTrue(Envelope.looksLikeEnvelope(decoded));
    }

    @Test
    void wrongPepperFailsClosed() {
        HardenedCollection h = build();
        String path = h.createItem("x", "the-secret").orElseThrow();

        KeyMaterialProvider wrongProvider = new EnvVarKeyMaterialProvider("a-different-pepper");
        HardenedCollection other = HardenedCollection.builder(fake, wrongProvider)
                .acknowledgeSameUidExposure(true)
                .build();

        Optional<String> res = other.withSecret(path, String::new);
        assertTrue(res.isEmpty(), "wrong pepper must not decrypt");
    }

    @Test
    void refusesPlaintextItemInSharedCollection() {
        Map<String, String> attrs = new HashMap<>();
        attrs.put("application", "legacy");
        fake.seedPlain("/path/legacy-item", "legacy-label", "legacy-plaintext", attrs);

        HardenedCollection h = build();
        Optional<String> res = h.withSecret("/path/legacy-item", String::new);
        assertTrue(res.isEmpty(), "must not expose plaintext of non-hardened items");

        assertFalse(h.deleteItem("/path/legacy-item"), "must refuse to delete non-hardened items");
        assertTrue(fake.rawItems().containsKey("/path/legacy-item"), "legacy item must remain untouched");
    }

    @Test
    void rejectsReservedAttributeNamespace() {
        HardenedCollection h = build();
        Map<String, String> bad = new HashMap<>();
        bad.put("hardened.custom", "nope");
        assertThrows(IllegalArgumentException.class,
                () -> h.createItem("x", "secret", bad));
    }

    @Test
    void statusReportsProviderAndAlgorithms() {
        HardenedCollection h = build();
        HardenedStatus s = h.status();
        assertNotNull(s.epochId());
        assertEquals("aes-256-gcm", s.aeadAlgorithm());
        assertEquals("hkdf-sha256", s.kdfAlgorithm());
        assertFalse(s.resistsSameUidAttacker(), "EnvVar provider must report theater");
        assertFalse(s.memoryLocked(), "memoryLocked must be false unless lockMemory(true) is set");
        assertNotNull(s.epochCreated());
    }

    @Test
    void lockMemoryAttemptsAndReportsHonestly() {
        // lockMemory(true) attempts mlockall; on a box with a low RLIMIT_MEMLOCK the lock fails and
        // memoryLocked() reports false -- the point is it reflects the ACTUAL syscall result (never a
        // hardcoded value) and construction never throws.
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .lockMemory(true)
                .build();
        assertNotNull(h.status(), "lockMemory(true) must not break construction or status()");
        String path = h.createItem("x", "s").orElseThrow();
        assertEquals("s", h.withSecret(path, String::new).orElse(null),
                "items still round-trip with lockMemory enabled");
    }

    /**
     * Fails the first {@code n} createItem calls that write a real ITEM (not the epoch keystore).
     * A one-shot {@code setNextCreateItemFails} can no longer target a rewrap: rotation commits the
     * new epoch to the keystore first, so the first createItem of a rotation is that persist.
     */
    private void failFirstItemWrites(int n) {
        java.util.concurrent.atomic.AtomicInteger left = new java.util.concurrent.atomic.AtomicInteger(n);
        fake.setCreateItemFailsWhen(attrs ->
                !EpochKeystore.KIND_VALUE.equals(attrs.get(EpochKeystore.ATTR_KIND))
                        && left.getAndDecrement() > 0);
    }

    @Test
    void withSecretsFailsFastOnAnyItemFailure() {
        HardenedCollection h = build();
        String targetPath = h.createItem("ok1", "good-1").orElseThrow();
        h.createItem("ok2", "good-2").orElseThrow();
        // Tamper the first hardened item's envelope so decryption fails. (Capture the path from
        // createItem rather than iterating rawItems, which now also contains the keystore item.)
        fake.overwriteRawSecret(targetPath, "!!!not-base64!!!");

        Optional<Integer> res = h.withSecrets(map -> map.size());
        assertTrue(res.isEmpty(),
                "withSecrets must return empty when any item fails to decrypt -- not a truncated map");
    }

    @Test
    void withSecretsScopesToHardenedItemsOnly() {
        // Foreign (non-hardened) items in the same collection must be invisible to withSecrets.
        HardenedCollection h = build();
        h.createItem("hardened-a", "plain-a").orElseThrow();
        fake.seedPlain("/legacy/1", "legacy", "foreign", Map.of("app", "other"));

        Optional<Integer> res = h.withSecrets(map -> map.size());
        assertEquals(1, res.orElse(-1), "only the one hardened item is visible to withSecrets");
    }

    @Test
    void matchesSecretReturnsTrueForEquality() {
        HardenedCollection h = build();
        String path = h.createItem("x", "correct-horse-battery-staple").orElseThrow();

        char[] typed = "correct-horse-battery-staple".toCharArray();
        assertEquals(Boolean.TRUE, h.matchesSecret(path, typed).orElse(null));
        // candidate must be zeroed after the call
        for (char c : typed) assertEquals('\0', c, "candidate char[] must be zeroed on return");
    }

    @Test
    void matchesSecretReturnsFalseForMismatch() {
        HardenedCollection h = build();
        String path = h.createItem("x", "correct-horse-battery-staple").orElseThrow();

        char[] typed = "wrong-guess-abcde".toCharArray();
        assertEquals(Boolean.FALSE, h.matchesSecret(path, typed).orElse(null));
        for (char c : typed) assertEquals('\0', c, "candidate char[] must be zeroed even on mismatch");
    }

    @Test
    void matchesSecretReturnsFalseForLengthMismatch() {
        HardenedCollection h = build();
        String path = h.createItem("x", "short").orElseThrow();
        char[] typed = "short-but-longer".toCharArray();
        assertEquals(Boolean.FALSE, h.matchesSecret(path, typed).orElse(null));
    }

    @Test
    void matchesSecretEmptyForNonHardenedItem() {
        HardenedCollection h = build();
        fake.seedPlain("/legacy", "legacy", "plaintext", Map.of());
        char[] typed = "plaintext".toCharArray();
        assertTrue(h.matchesSecret("/legacy", typed).isEmpty(),
                "non-hardened items are invisible to matchesSecret");
        for (char c : typed) assertEquals('\0', c,
                "candidate must be zeroed even when the item was rejected");
    }

    @Test
    void matchesSecretEmptyForMissingItem() {
        HardenedCollection h = build();
        char[] typed = "anything".toCharArray();
        assertTrue(h.matchesSecret("/no/such/path", typed).isEmpty());
        for (char c : typed) assertEquals('\0', c);
    }

    @Test
    void matchesSecretEmptyForTamperedEnvelope() {
        HardenedCollection h = build();
        String path = h.createItem("x", "value").orElseThrow();
        fake.overwriteRawSecret(path, "!!!not-base64!!!");
        char[] typed = "value".toCharArray();
        assertTrue(h.matchesSecret(path, typed).isEmpty());
        for (char c : typed) assertEquals('\0', c);
    }

    @Test
    void postQuantumItemsStayReadableWhenPostQuantumIsTurnedBackOff() {
        // Regression: the read path gated the ML-KEM half on postQuantumAvailable, which is the
        // WRITE-side preference (enablePostQuantum). Flipping the flag back off therefore dropped
        // half the shared secret for envelopes that carry a PQ ciphertext, producing a wrong DEK
        // and surfacing as "AEAD authentication failed" -- reporting a config change as tampering,
        // and contradicting the builder javadoc's promise that old envelopes remain readable.
        HardenedCollection pq = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .enablePostQuantum(true)
                .build();
        String path = pq.createItem("pq-item", "written-with-pq-on").orElseThrow();

        // Same collection and pepper, PQ now disabled -- i.e. a config refactor dropped the flag.
        HardenedCollection classical = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .enablePostQuantum(false)
                .build();

        Optional<Boolean> matched = classical.matchesSecret(path, "written-with-pq-on".toCharArray());
        assertTrue(matched.isPresent() && matched.get(),
                "an item written under PQ must stay readable after enablePostQuantum is turned off");
    }

    @Test
    void corruptKemCiphertextLengthReturnsEmptyInsteadOfThrowing() {
        // Regression: Envelope only checks that kem_ct_len does not overrun the buffer, so a
        // flipped byte at rest (kem_ct_len = 1) parses fine and then made unpackKemCiphertext
        // throw IllegalArgumentException. Only IllegalStateException was caught, so the unchecked
        // exception escaped withSecret/matchesSecret -- which are contractually Optional-returning
        // -- and skipped the pepper zeroing on the way out.
        HardenedCollection h = build();
        String path = h.createItem("x", "value").orElseThrow();

        // Rebuild the stored envelope with a 1-byte kem_ct: structurally parseable, semantically junk.
        Envelope env = Envelope.fromBytes(Base64.getDecoder().decode(fake.rawItems().get(path).rawSecret()));
        Envelope corrupt = new Envelope(Envelope.VERSION_3, env.flags(), env.aeadId(), env.kdfId(),
                env.kemId(), env.salt(), env.epochId(), env.itemId(),
                new byte[]{0x01}, env.nonce(), env.aeadCiphertext());
        fake.overwriteRawSecret(path, Base64.getEncoder().encodeToString(corrupt.toBytes()));

        assertTrue(h.withSecret(path, s -> new String(s)).isEmpty(),
                "a corrupt kem_ct must yield an empty Optional, not a thrown exception");
        char[] typed = "value".toCharArray();
        assertTrue(h.matchesSecret(path, typed).isEmpty());
        for (char c : typed) assertEquals('\0', c, "the caller's buffer is still zeroed on this path");
    }

    @Test
    void twoInstancesShareOneEpochInsteadOfAccumulating() {
        // F8: the epoch is a property of the COLLECTION, not of the instance. Each new
        // HardenedCollection used to mint a fresh UUID epoch and add a keypair to the single
        // keystore item on its first write -- unbounded growth across process lifetimes, shrinkable
        // only by a fully-successful rotateEpoch().
        HardenedCollection h1 = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true).build();
        String p1 = h1.createItem("a", "one").orElseThrow();

        HardenedCollection h2 = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true).build();
        String p2 = h2.createItem("b", "two").orElseThrow();

        assertEquals(fake.rawItems().get(p1).attrs().get(HardenedCollection.ATTR_EPOCH),
                fake.rawItems().get(p2).attrs().get(HardenedCollection.ATTR_EPOCH),
                "a second instance must discover and reuse the collection's epoch");
        EpochKeystore ks = new EpochKeystore(fake, provider);
        ks.peekCurrent(); // sizeForTest() reads the in-memory map; force the load first
        assertEquals(1, ks.sizeForTest(), "one epoch entry, not one per instance");
        // Both remain readable from either instance.
        assertTrue(h2.withSecret(p1, String::new).isPresent());
        assertTrue(h1.withSecret(p2, String::new).isPresent());
    }

    @Test
    void statusReportsUnresolvedEpochBeforeTheFirstWrite() {
        // Resolution is lazy (the constructor does no D-Bus I/O), but HardenedStatus requires a
        // non-null epoch, so status() must report a sentinel rather than null or perform I/O.
        HardenedCollection h = build();
        assertEquals(HardenedCollection.EPOCH_UNRESOLVED, h.status().epochId());
        h.createItem("x", "v").orElseThrow();
        assertNotEquals(HardenedCollection.EPOCH_UNRESOLVED, h.status().epochId(),
                "the first write resolves the collection's epoch");
    }

    @Test
    void enablingPostQuantumOverAnExistingCollectionKeepsEverythingReadable() {
        // The documented upgrade path. kem_id used to be stamped from the RUNTIME PQ preference
        // while the actual encapsulation fell back to classical (the recorded epoch, minted while
        // PQ was off, has no ML-KEM half). The envelope then advertised FLAG_PQ_HYBRID over a
        // classical-only kem_ct and was unreadable forever -- createItem still returned a path, so
        // the loss was silent. Now kem_id follows what was actually encapsulated, and the epoch
        // gains its ML-KEM half when PQ becomes available.
        HardenedCollection classical = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .enablePostQuantum(false)
                .build();
        String beforePath = classical.createItem("pre", "written-without-pq").orElseThrow();

        HardenedCollection pq = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .enablePostQuantum(true)
                .build();
        String afterPath = pq.createItem("post", "written-with-pq-on").orElseThrow();

        assertEquals("written-with-pq-on", pq.withSecret(afterPath, String::new).orElse(null),
                "an item written after enabling PQ must be readable");
        assertEquals("written-without-pq", pq.withSecret(beforePath, String::new).orElse(null),
                "the pre-existing classical item must stay readable");

        // The stamped kem_id must match reality: whatever the envelope advertises, it must decrypt.
        Envelope env = Envelope.fromBytes(
                Base64.getDecoder().decode(fake.rawItems().get(afterPath).rawSecret()));
        boolean advertisesPq = KemId.fromId(env.kemId()).map(KemId::carriesPqCiphertext).orElse(false);
        if (advertisesPq) {
            assertTrue(env.kemCiphertext().length > 32,
                    "an envelope stamped PQ-hybrid must actually carry the ML-KEM ciphertext");
        }
    }

    @Test
    void sharingOneGenerationAnchorAcrossCollectionsIsRefused() {
        // The floor is global but each collection keeps its own generation seeded from it, so two
        // collections sharing an anchor push each other below the floor; both are then refused as
        // rollbacks and fail closed on reads AND writes. Refuse at construction instead.
        EpochKeystoreTest.FakeAnchor shared = new EpochKeystoreTest.FakeAnchor();
        FakeCollection other = new FakeCollection();

        HardenedCollection first = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .generationAnchor(shared)
                .build();

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> HardenedCollection.builder(other, provider)
                        .acknowledgeSameUidExposure(true)
                        .generationAnchor(shared)
                        .build(),
                "a second collection on the same anchor must be refused");
        assertTrue(e.getMessage().contains("exactly one collection"), e.getMessage());

        // Closing the first releases the anchor for a replacement instance.
        first.close();
        HardenedCollection replacement = HardenedCollection.builder(other, provider)
                .acknowledgeSameUidExposure(true)
                .generationAnchor(shared)
                .build();
        assertNotNull(replacement);
        replacement.close();
    }

    @Test
    void aRefusedBuildDoesNotPoisonTheAnchorRegistry() {
        // The anchor was registered BEFORE the same-UID gate could throw, so a refused build() left
        // an entry behind forever -- and a later, correct collection over a DIFFERENT collection was
        // then refused, blaming a collection that was never constructed.
        EpochKeystoreTest.FakeAnchor anchor = new EpochKeystoreTest.FakeAnchor();
        FakeCollection other = new FakeCollection();

        assertThrows(SameUidExposureException.class,
                () -> HardenedCollection.builder(fake, provider)   // no acknowledgement -> refused
                        .generationAnchor(anchor)
                        .build());

        // The anchor was never actually claimed, so a different collection may use it.
        try (HardenedCollection ok = HardenedCollection.builder(other, provider)
                .acknowledgeSameUidExposure(true)
                .generationAnchor(anchor)
                .build()) {
            assertNotNull(ok);
        }
    }

    @Test
    void reservedKemIdIsMarkedUnimplementedSoTheReaderCanRefuseIt() {
        // decryptToChars guarded aead_id and kdf_id but not kem_id, so an id this build cannot
        // execute was decapsulated as classical (unknown ids) or fed to ML-KEM (the reserved
        // hqc-192 id) and surfaced as "AEAD authentication failed" -- a format/config problem
        // reported as forgery, which Envelope's javadoc explicitly promises not to do.
        //
        // The guard itself is not observable through the public API: the AAD covers kem_id, so an
        // envelope whose id we TAMPER with fails authentication either way. It matters for an
        // envelope legitimately written by a future version, which cannot be forged from outside.
        // So this pins the classification the guard reads.
        assertTrue(KemId.X25519.implemented());
        assertTrue(KemId.X25519_MLKEM768.implemented());
        assertTrue(KemId.NONE.implemented());
        assertFalse(KemId.X25519_HQC192.implemented(),
                "hqc-192 is a reserved id with no implementation; the reader must refuse it rather "
                        + "than route it into the ML-KEM path");
        assertTrue(KemId.fromId((byte) 0x7f).isEmpty(), "an unknown id resolves to nothing");
    }

    @Test
    void tamperedKemIdStillFailsClosed() {
        // Belt and braces: whatever the suite guard decides, a rewritten kem_id must never decrypt,
        // because the byte is covered by the AEAD associated data.
        HardenedCollection h = build();
        String path = h.createItem("x", "value").orElseThrow();
        Envelope env = Envelope.fromBytes(Base64.getDecoder().decode(fake.rawItems().get(path).rawSecret()));

        for (byte kemId : new byte[]{Envelope.KEM_ID_X25519_HQC192, (byte) 0x7f}) {
            Envelope other = new Envelope(Envelope.VERSION_3, env.flags(), env.aeadId(), env.kdfId(),
                    kemId, env.salt(), env.epochId(), env.itemId(),
                    env.kemCiphertext(), env.nonce(), env.aeadCiphertext());
            fake.overwriteRawSecret(path, Base64.getEncoder().encodeToString(other.toBytes()));
            assertTrue(h.withSecret(path, String::new).isEmpty(),
                    "kem_id 0x" + Integer.toHexString(kemId & 0xff) + " must not decrypt");
        }
    }

    @Test
    void constantTimeEqualsIsLengthIndependentOfFirstMismatchIndex() {
        // Correctness (not timing) check: equality and mismatch outcomes are right regardless
        // of where the first difference lies. We cannot measure timing reliably from JUnit,
        // but we can pin the mathematical contract.
        assertTrue(HardenedCollection.constantTimeEquals("abcdef".toCharArray(), "abcdef".toCharArray()));
        assertFalse(HardenedCollection.constantTimeEquals("Xbcdef".toCharArray(), "abcdef".toCharArray()));
        assertFalse(HardenedCollection.constantTimeEquals("abcdeX".toCharArray(), "abcdef".toCharArray()));
        assertFalse(HardenedCollection.constantTimeEquals("abcdef".toCharArray(), "abcde".toCharArray()));
        assertFalse(HardenedCollection.constantTimeEquals(null, "abcdef".toCharArray()));
        assertFalse(HardenedCollection.constantTimeEquals("abcdef".toCharArray(), null));
    }

    @Test
    void chaCha20Poly1305RoundTrips() {
        // The AEAD is selectable; ChaCha20-Poly1305 items round-trip and stamp aead_id=0x02.
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSameUidExposure(true)
                .aead(AeadId.CHACHA20_POLY1305)
                .build();
        String path = h.createItem("c", "chacha-secret").orElseThrow();
        FakeCollection.Item stored = fake.rawItems().get(path);
        Envelope env = Envelope.fromBytes(Base64.getDecoder().decode(stored.rawSecret()));
        assertEquals(Envelope.AEAD_ID_CHACHA20_POLY1305, env.aeadId());
        assertEquals("chacha20-poly1305", stored.attrs().get(HardenedCollection.ATTR_AEAD));
        assertEquals("chacha-secret", h.withSecret(path, String::new).orElse(null));
    }

    @Test
    void concurrentCreateAndReadIsThreadSafe() throws Exception {
        // Cold start (no warm-up): many threads createItem at once, so the very first writes race
        // epoch creation. EpochKeystore.getOrCreate is synchronized, so exactly one epoch must be
        // created, every item must decrypt, and the keystore must not corrupt.
        HardenedCollection h = build();
        int threads = 8, perThread = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<List<String>>> futures = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                final int tid = t;
                futures.add(pool.submit(() -> {
                    List<String> paths = new ArrayList<>();
                    for (int i = 0; i < perThread; i++) {
                        paths.add(h.createItem("k-" + tid + "-" + i, "secret-" + tid + "-" + i).orElseThrow());
                    }
                    return paths;
                }));
            }
            List<String> allPaths = new ArrayList<>();
            for (Future<List<String>> f : futures) allPaths.addAll(f.get(30, TimeUnit.SECONDS));

            assertEquals(threads * perThread, allPaths.size(), "every concurrent createItem returned a path");
            for (String p : allPaths) {
                assertTrue(h.withSecret(p, String::new).orElse("").startsWith("secret-"),
                        "concurrently written item " + p + " must decrypt to its own value");
            }
            // A single epoch across every item -> no split-brain keystore under the write storm.
            Set<String> epochs = new HashSet<>();
            for (FakeCollection.Item it : fake.rawItems().values()) {
                String e = it.attrs().get(HardenedCollection.ATTR_EPOCH);
                if (e != null) epochs.add(e);
            }
            assertEquals(1, epochs.size(), "all concurrent writes must land under a single epoch");
        } finally {
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        }
    }
}
