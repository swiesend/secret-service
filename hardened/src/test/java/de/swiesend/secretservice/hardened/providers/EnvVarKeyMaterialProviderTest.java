package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
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
        assertThrows(IllegalStateException.class,
                () -> new EnvVarKeyMaterialProvider(null, null, null));
        assertThrows(IllegalStateException.class,
                () -> new EnvVarKeyMaterialProvider("", null, null));
    }

    @Test
    void noTotpModeWhenSeedAbsent() {
        EnvVarKeyMaterialProvider p = new EnvVarKeyMaterialProvider("pepper-val", null, null);
        assertEquals(KeyMaterialProvider.Mode.NO_TOTP, p.mode());
        assertTrue(p.getTotpSeed().isEmpty());
    }

    @Test
    void storedStepModeWhenSeedPresent() {
        String seed = Base64.getEncoder().encodeToString("seed".getBytes());
        EnvVarKeyMaterialProvider p = new EnvVarKeyMaterialProvider("pepper-val", seed, null);
        assertEquals(KeyMaterialProvider.Mode.STORED_STEP, p.mode());
        assertTrue(p.getTotpSeed().isPresent());
    }

    @Test
    void modeOverrideHonored() {
        String seed = Base64.getEncoder().encodeToString("seed".getBytes());
        EnvVarKeyMaterialProvider p = new EnvVarKeyMaterialProvider("pepper", seed, "LIVE_CODE");
        assertEquals(KeyMaterialProvider.Mode.LIVE_CODE, p.mode());
    }

    @Test
    void threatCoverageDeclaresTheaterVsSameUid() {
        EnvVarKeyMaterialProvider p = new EnvVarKeyMaterialProvider("pepper", null, null);
        ThreatCoverage tc = p.threatCoverage();
        assertEquals(ThreatCoverage.Level.NONE, tc.sameUid());
        assertTrue(tc.isSecurityTheaterVsSameUid());
    }

    @Test
    void rejectsNonBase64Seed() {
        assertThrows(IllegalStateException.class,
                () -> new EnvVarKeyMaterialProvider("pepper", "not!base64!!", null));
    }

    @Test
    void generatePepperReturnsStrongLength() {
        String p = EnvVarKeyMaterialProvider.generatePepper();
        byte[] raw = Base64.getDecoder().decode(p);
        assertEquals(32, raw.length);
        assertFalse(p.isBlank());
    }
}
