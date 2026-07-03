package de.swiesend.secretservice.hardened.tpm2;

import org.junit.jupiter.api.Test;
import tss.Tpm;
import tss.TpmFactory;
import tss.tpm.TPM_HANDLE;

import java.io.IOException;
import java.net.Socket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for {@link Tpm2GenerationAnchor} and
 * {@link Tpm2Provisioner#defineGenerationCounter}. The round-trip tests require a TPM simulator on
 * {@code localhost:2321} and are skipped (via {@code Assumptions#assumeTrue}) when it is absent, so
 * CI without a simulator still passes.
 */
class Tpm2GenerationAnchorTest {

    // Distinct NV index per test method so re-runs against a persistent simulator don't collide on
    // an already-defined index. Owner NV range.
    private static final int NV_INDEX_A = 0x01800210;
    private static final int NV_INDEX_B = 0x01800211;
    private static final int NV_INDEX_C = 0x01800212;

    private static boolean simulatorReachable() {
        try (Socket s = new Socket("localhost", 2321)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static void undefineQuietly(int nvIndex) {
        try (Tpm tpm = TpmFactory.localTpmSimulator()) {
            tpm.NV_UndefineSpace(tpm._OwnerHandle, TPM_HANDLE.NV(nvIndex));
        } catch (Exception ignored) {
            // best-effort cleanup; index may not exist (TSS throws, which we swallow)
        }
    }

    @Test
    void classSurfaceIsWellFormed() {
        // Loads without a TPM and exposes the static factories.
        assertNotNull(Tpm2GenerationAnchor.class.getMethods());
    }

    @Test
    void undefinedCounterFailsFastAtConstruction() {
        assumeTrue(simulatorReachable(), "TPM simulator not reachable; skipping");
        undefineQuietly(NV_INDEX_C);
        // No counter defined at this index -> constructor must throw a clear IllegalStateException.
        assertThrows(IllegalStateException.class,
                () -> Tpm2GenerationAnchor.forSimulator(NV_INDEX_C, "pw".toCharArray()));
    }

    @Test
    void counterIsMonotonicAndAdvanceIsIdempotent() {
        assumeTrue(simulatorReachable(), "TPM simulator not reachable; skipping");
        undefineQuietly(NV_INDEX_A);
        char[] pw = "anchor-p@ss".toCharArray();
        Tpm2Provisioner.defineGenerationCounter(NV_INDEX_A, pw.clone(), TpmFactory::localTpmSimulator);

        try (Tpm2GenerationAnchor anchor = Tpm2GenerationAnchor.forSimulator(NV_INDEX_A, pw.clone())) {
            long base = anchor.read();
            assertTrue(base >= 1, "an initialised counter reads at least 1");

            long afterAdvance = anchor.advanceTo(base + 2);
            assertTrue(afterAdvance >= base + 2, "advanceTo must reach at least the target");
            assertEquals(afterAdvance, anchor.read(), "read reflects the advanced value");

            // Idempotent: advancing to a value already met does not move the counter.
            long unchanged = anchor.advanceTo(base); // base < current
            assertEquals(afterAdvance, unchanged, "advanceTo below the current value is a no-op");

            // Monotonic: it never goes backwards across reads.
            assertTrue(anchor.read() >= afterAdvance);
        } finally {
            undefineQuietly(NV_INDEX_A);
        }
    }

    @Test
    void anchorValueSurvivesReopen() {
        assumeTrue(simulatorReachable(), "TPM simulator not reachable; skipping");
        undefineQuietly(NV_INDEX_B);
        char[] pw = "anchor-p@ss".toCharArray();
        Tpm2Provisioner.defineGenerationCounter(NV_INDEX_B, pw.clone(), TpmFactory::localTpmSimulator);

        long advanced;
        try (Tpm2GenerationAnchor anchor = Tpm2GenerationAnchor.forSimulator(NV_INDEX_B, pw.clone())) {
            advanced = anchor.advanceTo(anchor.read() + 3);
        }
        // A fresh anchor over the same index must observe the same (non-decreased) value.
        try (Tpm2GenerationAnchor reopened = Tpm2GenerationAnchor.forSimulator(NV_INDEX_B, pw.clone())) {
            assertTrue(reopened.read() >= advanced, "the counter must not decrease across reopen");
        } finally {
            undefineQuietly(NV_INDEX_B);
        }
    }
}
