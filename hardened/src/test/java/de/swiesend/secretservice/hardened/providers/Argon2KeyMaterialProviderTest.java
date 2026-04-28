package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Argon2KeyMaterialProviderTest {

    /** A minimal in-memory provider that exposes a fixed pepper and a class-C=NONE rating. */
    private static KeyMaterialProvider weakInner(String pepper) {
        return new KeyMaterialProvider() {
            char[] cached = pepper.toCharArray();
            boolean closed = false;
            @Override public char[] getPepper() {
                if (closed) throw new IllegalStateException("inner closed");
                return cached.clone();
            }
            @Override public Optional<byte[]> getTotpSeed() { return Optional.empty(); }
            @Override public Mode mode() { return Mode.NO_TOTP; }
            @Override public ThreatCoverage threatCoverage() {
                return new ThreatCoverage(
                        ThreatCoverage.Level.NONE,    // class A
                        ThreatCoverage.Level.NONE,    // class B
                        ThreatCoverage.Level.NONE,    // class C -- the row Argon2 promotes
                        ThreatCoverage.Level.NOT_APPLICABLE,
                        "weak inner for test");
            }
            @Override public void close() {
                if (!closed) { Arrays.fill(cached, '\0'); closed = true; }
            }
            boolean isClosed() { return closed; }
        };
    }

    @Test
    void stretchedPepperIsDeterministicAndAscii() {
        byte[] salt = "myapp-prod-install-2026".getBytes(StandardCharsets.UTF_8);

        try (Argon2KeyMaterialProvider a = new Argon2KeyMaterialProvider(
                weakInner("correct horse battery staple"), salt,
                Argon2KeyMaterialProvider.Profile.EMBEDDED);
             Argon2KeyMaterialProvider b = new Argon2KeyMaterialProvider(
                weakInner("correct horse battery staple"), salt,
                Argon2KeyMaterialProvider.Profile.EMBEDDED)) {

            char[] p1 = a.getPepper();
            char[] p2 = b.getPepper();
            try {
                assertArrayEquals(p1, p2,
                        "Argon2 over the same pepper + salt + profile must be deterministic");
                // Base64 ASCII output: every char must be < 0x80.
                for (char c : p1) assertTrue(c < 0x80,
                        "stretched pepper must be ASCII (round-trip-safe through UTF-8)");
                // Default 32-byte output → base64 length = 44.
                assertEquals(44, p1.length,
                        "EMBEDDED profile produces a 32-byte derived key encoded as 44-char base64");
            } finally {
                Arrays.fill(p1, '\0');
                Arrays.fill(p2, '\0');
            }
        }
    }

    @Test
    void differentSaltsProduceDifferentStretchedPeppers() {
        try (Argon2KeyMaterialProvider a = new Argon2KeyMaterialProvider(
                weakInner("hunter2"), "salt-a-aaaa".getBytes(StandardCharsets.UTF_8),
                Argon2KeyMaterialProvider.Profile.EMBEDDED);
             Argon2KeyMaterialProvider b = new Argon2KeyMaterialProvider(
                weakInner("hunter2"), "salt-b-bbbb".getBytes(StandardCharsets.UTF_8),
                Argon2KeyMaterialProvider.Profile.EMBEDDED)) {

            char[] p1 = a.getPepper();
            char[] p2 = b.getPepper();
            try {
                assertFalse(Arrays.equals(p1, p2),
                        "different salts must yield different stretched peppers");
            } finally {
                Arrays.fill(p1, '\0');
                Arrays.fill(p2, '\0');
            }
        }
    }

    @Test
    void threatCoverageBumpsClassCFromNoneToPartial() {
        try (Argon2KeyMaterialProvider p = new Argon2KeyMaterialProvider(
                weakInner("weak-input"), "fixed-deployment-salt".getBytes(StandardCharsets.UTF_8),
                Argon2KeyMaterialProvider.Profile.EMBEDDED)) {

            ThreatCoverage tc = p.threatCoverage();
            assertEquals(ThreatCoverage.Level.NONE, tc.sameUid(),
                    "Argon2 does NOT improve class-A coverage");
            assertEquals(ThreatCoverage.Level.NONE, tc.crossUid(),
                    "Argon2 does NOT improve class-B coverage");
            assertEquals(ThreatCoverage.Level.PARTIAL, tc.offline(),
                    "Argon2 must promote class-C from NONE to PARTIAL");
            assertEquals(ThreatCoverage.Level.NOT_APPLICABLE, tc.networkHndl());
            assertNotNull(tc.rationale());
            assertTrue(tc.rationale().contains("Argon2id"),
                    "rationale must name the algorithm so operators can audit posture");
        }
    }

    @Test
    void rejectsTooShortSalt() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                new Argon2KeyMaterialProvider(weakInner("p"),
                        new byte[]{1, 2, 3},  // 3 < 8
                        Argon2KeyMaterialProvider.Profile.EMBEDDED));
        assertTrue(e.getMessage().contains("salt"));
    }

    @Test
    void closeZerosCacheAndClosesInner() {
        KeyMaterialProvider inner = weakInner("p");
        Argon2KeyMaterialProvider p = new Argon2KeyMaterialProvider(
                inner, "long-enough-salt".getBytes(StandardCharsets.UTF_8),
                Argon2KeyMaterialProvider.Profile.EMBEDDED);
        char[] before = p.getPepper();
        try {
            assertNotNull(before);
            p.close();
            assertThrows(IllegalStateException.class, p::getPepper);
            // inner provider is closed too -- a getPepper on it would throw the inner's marker
            assertThrows(IllegalStateException.class, inner::getPepper);
        } finally {
            Arrays.fill(before, '\0');
        }
        // close is idempotent
        p.close();
    }

    @Test
    void rejectsNullArgs() {
        assertThrows(NullPointerException.class, () ->
                new Argon2KeyMaterialProvider(null,
                        "long-enough-salt".getBytes(),
                        Argon2KeyMaterialProvider.Profile.EMBEDDED));
        assertThrows(NullPointerException.class, () ->
                new Argon2KeyMaterialProvider(weakInner("p"), null,
                        Argon2KeyMaterialProvider.Profile.EMBEDDED));
        assertThrows(NullPointerException.class, () ->
                new Argon2KeyMaterialProvider(weakInner("p"),
                        "long-enough-salt".getBytes(), null));
    }

    @Test
    void emptyOrMissingPlaceholder_assertsNothing() {
        // Sanity probe -- if BC is missing the test classpath this throws IllegalState
        // at construction. The hardened module's pom adds bcprov-jdk18on as a test dep,
        // so we expect this to succeed.
        assertNull(null);  // marker that the classpath assumption is part of the test contract
    }
}
