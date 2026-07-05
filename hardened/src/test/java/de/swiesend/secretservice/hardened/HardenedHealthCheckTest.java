package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HardenedHealthCheckTest {

    private FakeCollection fake;
    private HardenedCollection collection;

    @BeforeEach
    void setUp() {
        fake = new FakeCollection();
        KeyMaterialProvider weak = new EnvVarKeyMaterialProvider(
                "test-pepper-with-enough-length-for-derivation");
        collection = HardenedCollection.builder(fake, weak)
                .acknowledgeSecurityTheater(true)
                .build();
    }

    @Test
    void healthCheckWithoutCanaryReturnsReportWithProviderPosture() {
        HardenedHealthCheck.Report r = HardenedHealthCheck.check(collection, null);
        assertNotNull(r);
        assertFalse(r.canaryAttempted());
        assertFalse(r.canarySucceeded());
        assertNotNull(r.providerClass());
        assertTrue(r.providerClass().contains("KeyMaterialProvider"),
                "providerClass should be the KeyMaterialProvider implementation class name");
        assertNotNull(r.epochId());
        assertNotNull(r.threatCoverage());
    }

    @Test
    void healthCheckFailsWeakProvider() {
        HardenedHealthCheck.Report r = HardenedHealthCheck.check(collection, null);
        // EnvVarKeyMaterialProvider reports sameUid=NONE, which is now a hard FAIL: a provider with
        // no same-UID defense must not report HEALTHY, even without a canary.
        boolean hasSameUidFail = r.findings().stream()
                .anyMatch(f -> f.check().equals("provider.sameUid")
                        && f.severity() == HardenedHealthCheck.Severity.FAIL);
        assertTrue(hasSameUidFail,
                "weak provider must produce a 'provider.sameUid' FAIL finding");
        assertFalse(r.healthy(),
                "a sameUid=NONE provider must make the report UNHEALTHY");
    }

    @Test
    void healthCheckRoundTripsACanary() {
        // Write a canary, then health-check it.
        String canaryPath = collection.createItem("canary", "ok").orElseThrow();
        HardenedHealthCheck.Report r = HardenedHealthCheck.check(collection, canaryPath);
        assertTrue(r.canaryAttempted());
        assertTrue(r.canarySucceeded(), "canary read must succeed for a freshly written item");
        boolean canaryOk = r.findings().stream()
                .anyMatch(f -> f.check().equals("canary.read")
                        && f.severity() == HardenedHealthCheck.Severity.OK);
        assertTrue(canaryOk);
    }

    @Test
    void healthCheckMarksMissingCanaryAsFail() {
        HardenedHealthCheck.Report r = HardenedHealthCheck.check(
                collection, "/no/such/path");
        assertTrue(r.canaryAttempted());
        assertFalse(r.canarySucceeded());
        assertFalse(r.healthy(),
                "missing canary path must mark the report as UNHEALTHY");
        boolean hasFail = r.findings().stream()
                .anyMatch(f -> f.severity() == HardenedHealthCheck.Severity.FAIL);
        assertTrue(hasFail);
    }

    @Test
    void toReportContainsKeyDiagnostics() {
        String canaryPath = collection.createItem("canary", "ok").orElseThrow();
        HardenedHealthCheck.Report r = HardenedHealthCheck.check(collection, canaryPath);
        String text = r.toReport();
        assertTrue(text.contains("provider:"));
        assertTrue(text.contains("threat coverage:"));
        assertTrue(text.contains("canary read:"));
        assertTrue(text.contains("HEALTHY") || text.contains("UNHEALTHY"));
    }

    @Test
    void toMapIsJsonShaped() {
        String canaryPath = collection.createItem("c", "v").orElseThrow();
        HardenedHealthCheck.Report r = HardenedHealthCheck.check(collection, canaryPath);
        Map<String, Object> m = HardenedHealthCheck.toMap(r);
        assertEquals(true, m.get("canaryAttempted"));
        assertEquals(true, m.get("canarySucceeded"));
        assertNotNull(m.get("threatCoverage"));
        assertNotNull(m.get("findings"));
    }

    @Test
    void rejectsNullCollection() {
        assertThrows(NullPointerException.class,
                () -> HardenedHealthCheck.check(null, "/path"));
    }
}
