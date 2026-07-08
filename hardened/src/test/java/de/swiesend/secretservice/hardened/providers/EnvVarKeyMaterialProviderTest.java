package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnvVarKeyMaterialProviderTest {

    @Test
    void failsClosedOnMissingPepper() {
        assertThrows(IllegalStateException.class, () -> new EnvVarKeyMaterialProvider((String) null));
        assertThrows(IllegalStateException.class, () -> new EnvVarKeyMaterialProvider(""));
    }

    @Test
    void returnsThePepper() {
        EnvVarKeyMaterialProvider p = new EnvVarKeyMaterialProvider("pepper-val");
        assertEquals("pepper-val", new String(p.getPepper()));
    }

    @Test
    void threatCoverageDeclaresTheaterVsSameUid() {
        EnvVarKeyMaterialProvider p = new EnvVarKeyMaterialProvider("pepper");
        ThreatCoverage tc = p.threatCoverage();
        assertEquals(ThreatCoverage.Level.NONE, tc.sameUid());
        assertTrue(tc.isSecurityTheaterVsSameUid());
    }

    @Test
    void generatePepperReturnsStrongLength() {
        String p = EnvVarKeyMaterialProvider.generatePepper();
        byte[] raw = Base64.getDecoder().decode(p);
        assertEquals(32, raw.length);
        assertFalse(p.isBlank());
    }

    @Test
    void closeScrubsAndBlocksGetPepper() {
        EnvVarKeyMaterialProvider p = new EnvVarKeyMaterialProvider("pepper-value");
        char[] before = p.getPepper();
        assertEquals("pepper-value", new String(before));
        p.close();
        assertThrows(IllegalStateException.class, p::getPepper);
    }
}
