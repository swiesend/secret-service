package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import de.swiesend.secretservice.hardened.providers.NoTotpKeyMaterialProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashMap;
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
        return HardenedCollection.builder(fake)
                .keyMaterial(provider)
                .acknowledgeSecurityTheater(true)
                .build();
    }

    @Test
    void refusesWeakProviderWithoutAcknowledgement() {
        HardenedCollection.Builder b = HardenedCollection.builder(fake).keyMaterial(provider);
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
        HardenedCollection other = HardenedCollection.builder(fake)
                .keyMaterial(wrongProvider)
                .acknowledgeSecurityTheater(true)
                .build();

        Optional<String> res = other.withSecret(path, String::new);
        assertTrue(res.isEmpty(), "wrong pepper must not decrypt");
    }

    @Test
    void refusesPlaintextItemInSharedCollection() {
        // Pre-seed a plain item (e.g., the default collection case) and verify the decorator
        // refuses to read it and refuses to delete it.
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
    void rotateEpochPreservesReadabilityAndChangesStoredEpochId() {
        HardenedCollection h = build();
        String pathBefore = h.createItem("x", "secret-value").orElseThrow();
        String epochBefore = h.status().epochId();

        assertTrue(h.rotateEpoch());
        String epochAfter = h.status().epochId();
        assertNotEquals(epochBefore, epochAfter);

        // After rotation, the original path is gone (rewrapped as a new item) but the plaintext is
        // recoverable via the new path.
        Optional<java.util.List<String>> paths = fake.getItems(Map.of(
                HardenedCollection.ATTR_VERSION, HardenedCollection.ATTR_VERSION_V1));
        assertTrue(paths.isPresent() && paths.get().size() == 1);
        String newPath = paths.get().get(0);
        assertEquals("secret-value", h.withSecret(newPath, String::new).orElse(null));
        assertFalse(fake.rawItems().containsKey(pathBefore), "old path replaced by rewrap");
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
        HardenedCollection h = HardenedCollection.builder(fake)
                .keyMaterial(totpProvider)
                .acknowledgeSecurityTheater(true)
                .build();

        String path = h.createItem("t", "value-with-totp").orElseThrow();
        assertEquals("value-with-totp", h.withSecret(path, String::new).orElse(null));
    }
}
