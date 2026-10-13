package de.swiesend.secretservice.hardened.tpm2;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Tpm2AvailabilityTest {

    @Test
    void isAvailableReflectsTssJavaOnTheClasspath() {
        // In this module's test scope TSS.Java is on the classpath (pulled in via the
        // provided dep), so the preflight must report true.
        assertTrue(Tpm2Availability.isAvailable(),
                "TSS.Java is on the test classpath; preflight should report available");
    }

    @Test
    void installationHintMentionsTheArtifact() {
        String hint = Tpm2Availability.installationHint();
        assertNotNull(hint);
        assertTrue(hint.contains("com.microsoft.azure:TSS.Java"),
                "hint must name the Maven coordinates so operators can act on it");
    }
}
