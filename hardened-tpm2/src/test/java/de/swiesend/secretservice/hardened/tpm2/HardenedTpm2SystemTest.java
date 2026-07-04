package de.swiesend.secretservice.hardened.tpm2;

import de.swiesend.secretservice.ProviderDetector;
import de.swiesend.secretservice.ProviderDetector.Provider;
import de.swiesend.secretservice.functional.SearchMode;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.System;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import de.swiesend.secretservice.hardened.HardenedCollection;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tss.Tpm;
import tss.TpmFactory;

import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end system test for the TPM-sealed pepper path against a <b>real platform TPM 2.0</b>
 * and the <b>live Secret Service</b>, using a throwaway, non-default collection.
 *
 * <p>Unlike {@link Tpm2KeyMaterialProviderTest} (which targets the {@code localhost:2321}
 * simulator and exercises the provider in isolation), this test drives the full stack:
 * {@link Tpm2Provisioner#seal} → {@link Tpm2KeyMaterialProvider#forPlatformTpm} →
 * {@link HardenedCollection} → gnome-keyring over D-Bus. It proves the pepper is sealed and
 * unsealed on the actual chip and that application-layer AEAD encryption round-trips through a
 * live keyring.</p>
 *
 * <h3>Preconditions and skipping</h3>
 * <p>The suite uses {@link Assumptions} so it is safe to run anywhere: it skips cleanly when</p>
 * <ul>
 *   <li>TSS.Java is not on the classpath, or no usable TPM device is reachable
 *       (e.g. CI containers, missing {@code /dev/tpmrm0}, or the caller is not in the
 *       {@code tss} group), and</li>
 *   <li>the active Secret Service provider is not gnome-keyring — the only provider that lets
 *       the test create and later delete a dedicated throwaway collection non-interactively
 *       (via a master password, no GUI prompt).</li>
 * </ul>
 *
 * <h3>Safety</h3>
 * <p>The test never touches the user's default/login collection. It creates a uniquely named
 * {@code hardened-tpm2-systemtest-<uuid>} collection, and deletes it (and the sealed-blob temp
 * file) in teardown regardless of test outcome. Sealing uses only transient TPM handles, so no
 * persistent state is written to the chip.</p>
 *
 * <p>Excluded from the default build; run with {@code mvn test -Psystem-test} on a host with a
 * TPM 2.0 and gnome-keyring on the session bus.</p>
 */
@Tag("system-test")
@DisplayName("hardened-tpm2 real-TPM + live Secret Service system test")
class HardenedTpm2SystemTest {

    private static final Logger log = LoggerFactory.getLogger(HardenedTpm2SystemTest.class);

    /** Password that authorises the TPM unseal (the sealed object's auth value). */
    private static final char[] TPM_PASSWORD = "systemtest-tpm-unseal-pw".toCharArray();
    /** Master password for the throwaway gnome-keyring collection. */
    private static final char[] COLLECTION_PASSWORD = "systemtest-collection-master-pw".toCharArray();

    private SystemInterface system;
    private ServiceInterface service;
    private SessionInterface session;
    private CollectionInterface rawCollection;
    private HardenedCollection hardened;
    private Path blobPath;

    /** @return true if a real platform TPM can be opened (implies the {@code tss} group / device access). */
    private static boolean platformTpmReachable() {
        if (!Tpm2Availability.isAvailable()) return false;
        try (Tpm tpm = TpmFactory.platformTpm()) {
            return tpm != null;
        } catch (Throwable t) {
            // No device, no permission (not in tss group), or no TSS backend: skip rather than fail.
            log.info("Platform TPM not reachable, skipping: {}", t.toString());
            return false;
        }
    }

    @BeforeEach
    void setUp(@TempDir Path dir) throws IOException {
        Assumptions.assumeTrue(platformTpmReachable(),
                "No usable platform TPM 2.0 (TSS.Java missing, /dev/tpmrm0 absent, or caller not in 'tss' group)");

        system = System.connect().orElse(null);
        Assumptions.assumeTrue(system != null, "Could not connect to D-Bus");

        Provider provider = ProviderDetector.detectProvider(system.getConnection());
        // The test creates and deletes a dedicated collection; only gnome-keyring supports that
        // non-interactively. Other providers would require a pre-existing DB or a GUI prompt.
        Assumptions.assumeTrue(provider == Provider.GNOME_KEYRING,
                "Active provider is " + provider + "; this test needs gnome-keyring to create a throwaway collection");

        service = SecretService.create(Optional.of(system)).orElse(null);
        Assumptions.assumeTrue(service != null, "SecretService not available");

        session = service.openSession().orElse(null);
        Assumptions.assumeTrue(session != null, "Could not open session");

        // Seal a random pepper inside the real TPM (transient handles only) -> 0600 temp blob.
        byte[] pepper = new byte[32];
        new SecureRandom().nextBytes(pepper);
        Tpm2SealedBlob sealed = Tpm2Provisioner.seal(pepper, TPM_PASSWORD.clone(), TpmFactory::platformTpm);
        Arrays.fill(pepper, (byte) 0);
        blobPath = dir.resolve("pepper.tpm2blob");
        sealed.writeTo(blobPath);

        // Real unseal on the chip.
        Tpm2KeyMaterialProvider provider0 = Tpm2KeyMaterialProvider.forPlatformTpm(blobPath, TPM_PASSWORD.clone());

        // Dedicated, uniquely named, NON-default collection.
        String label = "hardened-tpm2-systemtest-" + UUID.randomUUID();
        rawCollection = session.collection(label, Optional.of(CharBuffer.wrap(COLLECTION_PASSWORD))).orElse(null);
        assertNotNull(rawCollection, "could not create throwaway collection '" + label + "'");
        assertTrue(rawCollection.getLabel().orElse("").startsWith("hardened-tpm2-systemtest-"),
                "sanity: must operate on the dedicated collection, never the default");

        hardened = HardenedCollection.builder(rawCollection, provider0).build();
        log.info("HardenedCollection ready: provider={}, collection={}",
                hardened.providerClassName(), label);
    }

    @AfterEach
    void tearDown() throws Exception {
        // Delete the throwaway collection while the connection is live, then release everything.
        if (rawCollection != null) {
            try {
                assertTrue(rawCollection.delete(), "throwaway collection should delete cleanly");
            } catch (RuntimeException e) {
                log.warn("collection cleanup failed: {}", e.toString());
            }
        }
        if (hardened != null) hardened.close();   // zeroes the pepper cache, releases TPM, closes wrapped
        if (session != null) session.close();
        if (service != null) service.close();
        if (system != null) system.close();
        // blobPath lives under @TempDir and is removed by JUnit.
    }

    @Test
    @DisplayName("pepper seals + unseals on the real TPM and a secret round-trips through gnome-keyring")
    void tpmSealedSecretRoundTrip() {
        String plaintext = "correct-horse-battery-staple-✅-42"; // non-ASCII exercises the UTF-8 path
        Map<String, String> attrs = Map.of("application", "hardened-tpm2-systemtest");

        String itemPath = hardened.createItem("systemtest-secret", plaintext, attrs).orElse(null);
        assertNotNull(itemPath, "createItem returned empty");

        // Decrypted round-trip via the hardened layer (TPM-sealed pepper feeds the DEK).
        char[] expected = plaintext.toCharArray();
        Optional<Boolean> match = hardened.withSecret(itemPath, chars -> Arrays.equals(chars, expected));
        assertEquals(Optional.of(Boolean.TRUE), match, "hardened round-trip must recover the exact plaintext");

        // The raw stored value is the base64 AEAD envelope, never the plaintext.
        Optional<Boolean> rawIsCiphertext = rawCollection.withSecret(itemPath, chars -> {
            String raw = new String(chars);
            return !raw.contains("correct-horse") && raw.length() > plaintext.length();
        });
        assertEquals(Optional.of(Boolean.TRUE), rawIsCiphertext,
                "raw stored value must be an encrypted envelope, not plaintext");

        // Findable by its user attribute; hardened.* attributes are managed by the layer.
        List<String> byAttr = rawCollection.search("hardened-tpm2-systemtest", SearchMode.BY_ATTRIBUTE_VALUE);
        assertTrue(byAttr.contains(itemPath), "item should be discoverable by its application attribute");

        // Delete via the hardened layer (guards against cross-layer deletes).
        assertTrue(hardened.deleteItem(itemPath), "hardened deleteItem should succeed");
        assertFalse(rawCollection.getItems(attrs).orElse(List.of()).contains(itemPath),
                "item should be gone after deletion");
    }

    @Test
    @DisplayName("the TPM enforces the unseal password: a wrong password fails closed")
    void wrongUnsealPasswordFailsClosed() {
        assertThrows(IOException.class,
                () -> Tpm2KeyMaterialProvider.forPlatformTpm(blobPath, "WRONG-PASSWORD".toCharArray()),
                "unseal with the wrong password must fail the TPM authorisation as a checked IOException");
    }

    @Test
    @DisplayName("the TPM-sealed provider advertises honest same-UID=PARTIAL threat coverage")
    void providerAdvertisesHonestThreatCoverage() throws IOException {
        try (Tpm2KeyMaterialProvider provider = Tpm2KeyMaterialProvider.forPlatformTpm(blobPath, TPM_PASSWORD.clone())) {
            ThreatCoverage tc = provider.threatCoverage();
            assertEquals(ThreatCoverage.Level.PARTIAL, tc.sameUid(),
                    "TPM-sealed provider must advertise sameUid=PARTIAL (real same-UID defense needs a MAC policy)");
            assertEquals(ThreatCoverage.Level.REAL, tc.offline(),
                    "the TPM defends against offline blob theft");
            assertTrue(tc.rationale().contains("MAC policy"),
                    "rationale must name the MAC prerequisite for same-UID defense");
        }
    }
}
