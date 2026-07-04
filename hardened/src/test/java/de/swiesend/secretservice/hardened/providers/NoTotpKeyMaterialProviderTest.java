package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NoTotpKeyMaterialProviderTest {

    /** Records whether close() reached the delegate, and pins currentStep. */
    private static final class RecordingProvider implements KeyMaterialProvider {
        boolean closed = false;
        @Override public char[] getPepper() { return "delegate-pepper".toCharArray(); }
        @Override public Optional<byte[]> getTotpSeed() { return Optional.of(new byte[]{1, 2, 3}); }
        @Override public long currentStep() { return 424242L; }
        @Override public Mode mode() { return Mode.STORED_STEP; }
        @Override public ThreatCoverage threatCoverage() {
            return new ThreatCoverage(ThreatCoverage.Level.REAL, ThreatCoverage.Level.REAL,
                    ThreatCoverage.Level.REAL, ThreatCoverage.Level.NOT_APPLICABLE, "delegate");
        }
        @Override public void close() { closed = true; }
    }

    @Test
    void forcesNoTotpButForwardsPepperAndStepAndCoverage() {
        RecordingProvider delegate = new RecordingProvider();
        NoTotpKeyMaterialProvider p = new NoTotpKeyMaterialProvider(delegate);
        assertEquals(KeyMaterialProvider.Mode.NO_TOTP, p.mode());
        assertTrue(p.getTotpSeed().isEmpty(), "NO_TOTP decorator must hide any delegate seed");
        assertEquals("delegate-pepper", new String(p.getPepper()));
        assertEquals(424242L, p.currentStep(), "currentStep must forward to the delegate");
        assertEquals(ThreatCoverage.Level.REAL, p.threatCoverage().sameUid());
    }

    @Test
    void closePropagatesToDelegate() {
        RecordingProvider delegate = new RecordingProvider();
        NoTotpKeyMaterialProvider p = new NoTotpKeyMaterialProvider(delegate);
        p.close();
        assertTrue(delegate.closed, "closing the decorator must scrub the wrapped provider");
    }
}
