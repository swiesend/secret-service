package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import de.swiesend.secretservice.hardened.providers.NoTotpKeyMaterialProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
}
