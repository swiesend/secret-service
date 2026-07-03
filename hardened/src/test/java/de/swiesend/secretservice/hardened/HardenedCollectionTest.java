package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import de.swiesend.secretservice.hardened.providers.NoTotpKeyMaterialProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
        provider = new NoTotpKeyMaterialProvider(
                new EnvVarKeyMaterialProvider(pepper, null, null)
        );
    }

    private HardenedCollection build() {
        return HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
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
        SecurityTheaterException e = assertThrows(SecurityTheaterException.class, b::build);
        assertTrue(e.getMessage().contains("theater") || e.getMessage().contains("NONE"));
    }

    @Test
    void createAndReadRoundTrip() {
        HardenedCollection h = build();
        Optional<String> path = h.createItem("my-label", "s3cr3t-password");
        assertTrue(path.isPresent());

        Optional<String> fetched = h.withSecret(path.get(), chars -> new String(chars));
        assertEquals("s3cr3t-password", fetched.orElse(null));
    }

    @Test
    void migrateRefusesWithoutBuilderFlag() {
        // No .allowMigration(true) on the builder -> SecurityTheaterException
        HardenedCollection h = build();
        SecurityTheaterException e = assertThrows(SecurityTheaterException.class,
                () -> h.migrateNonHardenedToHardened(c -> true));
        assertTrue(e.getMessage().contains("allowMigration"));
    }

    @Test
    void migrateRefusesWithoutEnvVar() {
        // Builder flag set, but env var missing -> SecurityTheaterException
        // (unless this test runs with the env var actually set, in which case skip).
        if ("1".equals(System.getenv(HardenedCollection.ENV_ALLOW_MIGRATION))) {
            return;
        }
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
                .allowMigration(true)
                .build();
        SecurityTheaterException e = assertThrows(SecurityTheaterException.class,
                () -> h.migrateNonHardenedToHardened(c -> true));
        assertTrue(e.getMessage().contains(HardenedCollection.ENV_ALLOW_MIGRATION));
    }

    @Test
    void migrationBodyConvertsPlainItemsToHardened() {
        // Pre-seed a couple of plain items in the wrapped collection.
        fake.seedPlain("/legacy/a", "leg-a", "plain-a", Map.of("source", "legacy"));
        fake.seedPlain("/legacy/b", "leg-b", "plain-b", Map.of("source", "legacy"));
        fake.seedPlain("/legacy/c", "leg-c", "plain-c", Map.of("source", "other"));

        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
                .allowMigration(true)
                .build();

        // Use the test-only hook (env var is awkward to set portably). Selector picks only
        // items with source=legacy.
        HardenedCollection.MigrationReport r = h.migrateNonHardenedToHardenedForTest(
                c -> "legacy".equals(c.attributes().get("source")));

        assertEquals(2, r.migrated(), "two items match the selector");
        assertEquals(1, r.skipped(), "the source=other item is skipped by the selector");
        assertEquals(0, r.failed());
        // Original plain items are gone:
        assertFalse(fake.rawItems().containsKey("/legacy/a"));
        assertFalse(fake.rawItems().containsKey("/legacy/b"));
        // Non-matching plain item remains:
        assertTrue(fake.rawItems().containsKey("/legacy/c"));
        // The two hardened items are readable through the wrapper, with original attributes preserved.
        long hardenedCount = fake.rawItems().values().stream()
                .filter(it -> "1".equals(it.attrs().get(HardenedCollection.ATTR_VERSION)))
                .filter(it -> "legacy".equals(it.attrs().get("source")))
                .count();
        assertEquals(2, hardenedCount);
    }

    @Test
    void closePropagatesToProvider() {
        // A provider that records its own close() call. HardenedCollection.close() must call it.
        java.util.concurrent.atomic.AtomicBoolean providerClosed = new java.util.concurrent.atomic.AtomicBoolean(false);
        KeyMaterialProvider counting = new KeyMaterialProvider() {
            @Override public char[] getPepper() { return "p3pper-of-decent-length-yo!".toCharArray(); }
            @Override public Optional<byte[]> getTotpSeed() { return Optional.empty(); }
            @Override public Mode mode() { return Mode.NO_TOTP; }
            @Override public ThreatCoverage threatCoverage() {
                return new ThreatCoverage(
                        ThreatCoverage.Level.PARTIAL, ThreatCoverage.Level.REAL,
                        ThreatCoverage.Level.REAL, ThreatCoverage.Level.NOT_APPLICABLE,
                        "test provider with close-tracking");
            }
            @Override public void close() { providerClosed.set(true); }
        };

        try (HardenedCollection h = HardenedCollection.builder(fake, counting).build()) {
            h.createItem("x", "secret").orElseThrow();
        }
        assertTrue(providerClosed.get(),
                "HardenedCollection.close() must propagate to provider.close()");
    }

    @Test
    void defaultBuilderWritesKemIdNone() {
        // Without enablePostQuantum(true), envelopes must carry kem_id=KEM_ID_NONE and
        // an empty kem_ct. The PQ flag is opt-in.
        HardenedCollection h = build();
        String path = h.createItem("x", "secret").orElseThrow();
        FakeCollection.Item stored = fake.rawItems().get(path);
        byte[] envBytes = Base64.getDecoder().decode(stored.rawSecret());
        Envelope env = Envelope.fromBytes(envBytes);
        assertEquals(Envelope.KEM_ID_NONE, env.kemId());
        assertEquals(0, env.kemCiphertext().length);
        assertEquals("0x00", stored.attrs().get(HardenedCollection.ATTR_KEM_ID));
    }

    @Test
    void postQuantumRoundTripWritesKemCtAndRecoversPlaintext() {
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
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
    void rotateEpochProvidesForwardSecrecyForPqItems() {
        // Write a PQ item, capture its envelope bytes, rotate the epoch, then try to read
        // the captured envelope as if it had been exfiltrated pre-rotation. The keystore's
        // previous-epoch entry has been destroyed, so decapsulation must fail.
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
                .enablePostQuantum(true)
                .build();

        String path = h.createItem("pre-rotate", "leaky-secret").orElseThrow();
        FakeCollection.Item snapshot = fake.rawItems().get(path);
        String capturedSecret = snapshot.rawSecret();
        Map<String, String> capturedAttrs = new HashMap<>(snapshot.attrs());

        assertTrue(h.rotateEpoch(), "rotateEpoch must succeed");

        // Re-seed the original (pre-rotate) item byte-for-byte at a fresh path so we can
        // ask the wrapper to read it as if it had survived rotation. Forward secrecy means
        // this read must fail because the old epoch's private key is destroyed.
        fake.seedRaw("/replay/pre-rotate", "pre-rotate", capturedSecret, capturedAttrs);
        Optional<String> recovered = h.withSecret("/replay/pre-rotate", String::new);
        assertTrue(recovered.isEmpty(),
                "Captured pre-rotation envelope must be unreadable after rotateEpoch destroys the old keypair");
    }

    @Test
    void rotateEpochDestroysAllSupersededEpochsNotJustPrevious() {
        // Two epochs accumulate in the keystore across "sessions": an oldest epoch (from an
        // earlier HardenedCollection instance) and a middle epoch. A single rotation must
        // destroy BOTH, not just the immediately-previous one -- otherwise a pre-rotation
        // backup plus the current keystore could still decapsulate the oldest envelope.
        HardenedCollection oldest = HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
                .enablePostQuantum(true)
                .epochId("epoch-oldest")
                .build();
        String pathOldest = oldest.createItem("oldest", "oldest-secret").orElseThrow();
        FakeCollection.Item snapshot = fake.rawItems().get(pathOldest);
        String capturedSecret = snapshot.rawSecret();
        Map<String, String> capturedAttrs = new HashMap<>(snapshot.attrs());

        // A later session under a different epoch; its keystore now holds {oldest, middle}.
        HardenedCollection middle = HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
                .enablePostQuantum(true)
                .epochId("epoch-middle")
                .build();
        middle.createItem("middle", "middle-secret").orElseThrow();

        assertTrue(middle.rotateEpoch(), "rotateEpoch must succeed");

        // The keystore must now hold exactly one epoch (the new one); both older epochs gone.
        EpochKeystore ks = new EpochKeystore(fake, provider);
        ks.get("epoch-oldest"); // triggers load
        assertEquals(1, ks.sizeForTest(), "keystore must retain exactly the new epoch");
        assertTrue(ks.get("epoch-oldest").isEmpty(), "oldest epoch key must be destroyed");
        assertTrue(ks.get("epoch-middle").isEmpty(), "middle epoch key must be destroyed");

        // A pre-rotation copy of the oldest envelope must no longer decrypt: forward secrecy
        // now covers epochs older than `previous`, which the old removeEpoch(previous) missed.
        fake.seedRaw("/replay/oldest", "oldest", capturedSecret, capturedAttrs);
        assertTrue(middle.withSecret("/replay/oldest", String::new).isEmpty(),
                "captured oldest-epoch envelope must be unreadable after rotation destroys its key");
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

        KeyMaterialProvider wrongProvider = new NoTotpKeyMaterialProvider(
                new EnvVarKeyMaterialProvider("a-different-pepper", null, null)
        );
        HardenedCollection other = HardenedCollection.builder(fake, wrongProvider)
                .acknowledgeSecurityTheater(true)
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
        assertEquals("none", s.timeBindingLabel());
    }

    @Test
    void rotateEpochCreatesThenDeletes() {
        // Atomicity invariant: the new envelope must exist before the old one is removed.
        HardenedCollection h = build();
        String pathBefore = h.createItem("x", "secret-value").orElseThrow();
        String epochBefore = h.status().epochId();

        assertTrue(h.rotateEpoch());
        String epochAfter = h.status().epochId();
        assertNotEquals(epochBefore, epochAfter);

        Optional<List<String>> paths = fake.getItems(Map.of(
                HardenedCollection.ATTR_VERSION, HardenedCollection.ATTR_VERSION_V1));
        assertTrue(paths.isPresent() && paths.get().size() == 1);
        String newPath = paths.get().get(0);
        assertEquals("secret-value", h.withSecret(newPath, String::new).orElse(null));
        assertFalse(fake.rawItems().containsKey(pathBefore), "old path replaced by rewrap");
    }

    @Test
    void rotateEpochSurvivesCreateFailure() {
        // Inject a failure on createItem: the old envelope must remain intact (no data loss).
        HardenedCollection h = build();
        String pathBefore = h.createItem("x", "must-not-be-lost").orElseThrow();
        fake.setNextCreateItemFails(true);

        boolean ok = h.rotateEpoch();
        assertFalse(ok, "rotateEpoch must report failure when create fails");
        assertTrue(fake.rawItems().containsKey(pathBefore),
                "old hardened item must survive a failed rewrap -- no data loss");
        assertEquals("must-not-be-lost",
                h.withSecret(pathBefore, String::new).orElse(null),
                "old envelope must still decrypt under the original epoch");
    }

    @Test
    void withSecretsFailsFastOnAnyItemFailure() {
        HardenedCollection h = build();
        h.createItem("ok1", "good-1").orElseThrow();
        h.createItem("ok2", "good-2").orElseThrow();
        // Tamper: flip one envelope's base64 inside the fake so decryption fails.
        String targetPath = fake.rawItems().keySet().iterator().next();
        FakeCollection.Item it = fake.rawItems().get(targetPath);
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
    void storedStepTotpRoundTripsWithSameSeed() {
        byte[] seed = "1234567890abcdef".getBytes();
        KeyMaterialProvider totpProvider = new KeyMaterialProvider() {
            final String pepperStr = "pepper-for-totp-test-xxxxx";
            @Override public char[] getPepper() { return pepperStr.toCharArray(); }
            @Override public Optional<byte[]> getTotpSeed() { return Optional.of(seed.clone()); }
            @Override public long currentStep() { return 12345L; }
            @Override public Mode mode() { return Mode.STORED_STEP; }
            @Override public ThreatCoverage threatCoverage() {
                return new ThreatCoverage(
                        ThreatCoverage.Level.NONE, ThreatCoverage.Level.REAL,
                        ThreatCoverage.Level.REAL, ThreatCoverage.Level.NOT_APPLICABLE,
                        "test provider");
            }
        };
        HardenedCollection h = HardenedCollection.builder(fake, totpProvider)
                .acknowledgeSecurityTheater(true)
                .build();

        String path = h.createItem("t", "value-with-totp").orElseThrow();
        assertEquals("value-with-totp", h.withSecret(path, String::new).orElse(null));
    }

    /** TOTP provider whose step is externally controlled and optionally advances on every call. */
    static final class SteppingTotpProvider implements KeyMaterialProvider {
        final byte[] seed = "1234567890abcdef".getBytes();
        final Mode mode;
        long step;
        boolean advanceOnEveryCall;

        SteppingTotpProvider(Mode mode, long step) { this.mode = mode; this.step = step; }

        @Override public char[] getPepper() { return "pepper-for-totp-test-xxxxx".toCharArray(); }
        @Override public Optional<byte[]> getTotpSeed() { return Optional.of(seed.clone()); }
        @Override public long currentStep() { return advanceOnEveryCall ? step++ : step; }
        @Override public Mode mode() { return mode; }
        @Override public ThreatCoverage threatCoverage() {
            return new ThreatCoverage(
                    ThreatCoverage.Level.NONE, ThreatCoverage.Level.REAL,
                    ThreatCoverage.Level.REAL, ThreatCoverage.Level.NOT_APPLICABLE,
                    "test provider");
        }
    }

    @Test
    void storedStepSurvivesStepRolloverDuringWrite() {
        // Regression: createItem used to call provider.currentStep() twice (once for DEK
        // derivation, once for the hardened.totp.step attribute). If the step rolled over
        // between the calls, the stored step no longer matched the derivation step and the
        // item became permanently undecryptable. The stepping provider advances the step on
        // EVERY call, so any double-call during write breaks the round-trip.
        SteppingTotpProvider provider = new SteppingTotpProvider(KeyMaterialProvider.Mode.STORED_STEP, 12345L);
        provider.advanceOnEveryCall = true;
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
                .build();

        String path = h.createItem("t", "survives-rollover").orElseThrow();
        char[] expected = "survives-rollover".toCharArray();
        assertEquals(Boolean.TRUE, h.withSecret(path, secret -> Arrays.equals(secret, expected)).orElse(null),
                "item written across a step rollover must stay readable in STORED_STEP mode");
    }
}
