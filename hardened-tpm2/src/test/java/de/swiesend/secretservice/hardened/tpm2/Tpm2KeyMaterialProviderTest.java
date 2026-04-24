package de.swiesend.secretservice.hardened.tpm2;

import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tss.TpmFactory;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for {@link Tpm2KeyMaterialProvider}. The round-trip test
 * requires a TPM simulator (IBM or Microsoft TSS TPM Simulator) listening on
 * {@code localhost:2321}. It is gated on probing the socket: when the simulator
 * is absent the test is skipped via {@code Assumptions#assumeTrue}, so CI
 * without a simulator still passes.
 *
 * <p>To enable: run {@code mspTSSSimulator} or {@code ibmswtpm2} in the
 * background before invoking {@code mvn test}.</p>
 */
class Tpm2KeyMaterialProviderTest {

    private static boolean simulatorReachable() {
        try (Socket s = new Socket("localhost", 2321)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @Test
    void classSurfaceIsWellFormed() {
        // Sanity probe that does not require a TPM: the class loads and exposes the
        // static factory methods and the KeyMaterialProvider interface.
        assertNotNull(Tpm2KeyMaterialProvider.class.getMethods());
    }

    @Test
    void rejectsOverPermissiveBlobFile(@TempDir Path dir) throws IOException {
        // A corrupt file rejected by Tpm2SealedBlob.readFrom is caught before the
        // TPM path is opened -- so this test runs without a simulator.
        Path bad = dir.resolve("bad.tpm2blob");
        java.nio.file.Files.write(bad, new byte[]{'X', 'X', 'X', 'X'});
        java.nio.file.attribute.PosixFileAttributeView view =
                java.nio.file.Files.getFileAttributeView(bad, java.nio.file.attribute.PosixFileAttributeView.class);
        if (view != null) {
            view.setPermissions(java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        }
        assertThrows(IOException.class,
                () -> Tpm2KeyMaterialProvider.forSimulator(bad, "pw".toCharArray()));
    }

    @Test
    void sealUnsealRoundTripViaSimulator(@TempDir Path dir) throws Exception {
        assumeTrue(simulatorReachable(),
                "TPM simulator not listening on localhost:2321; skipping. "
                        + "Run ibmswtpm2 or mspTSSSimulator locally to enable.");

        byte[] pepper = new byte[32];
        new java.security.SecureRandom().nextBytes(pepper);
        char[] password = "t3st-p@ssword".toCharArray();

        Tpm2SealedBlob blob = Tpm2Provisioner.seal(pepper, password.clone(), TpmFactory::localTpmSimulator);
        Path blobPath = dir.resolve("pepper.tpm2blob");
        blob.writeTo(blobPath);

        try (Tpm2KeyMaterialProvider provider = Tpm2KeyMaterialProvider.forSimulator(blobPath, password.clone())) {
            ThreatCoverage tc = provider.threatCoverage();
            assertEquals(ThreatCoverage.Level.PARTIAL, tc.sameUid(),
                    "TPM-sealed provider must advertise sameUid=PARTIAL (real same-UID defense "
                            + "requires an external MAC policy; see the class Javadoc).");
            assertTrue(tc.rationale().contains("MAC policy"),
                    "rationale must name the MAC prerequisite for same-UID defense");
            char[] roundTripped = provider.getPepper();
            try {
                byte[] unsealedBytes = new byte[roundTripped.length];
                for (int i = 0; i < roundTripped.length; i++) unsealedBytes[i] = (byte) roundTripped[i];
                assertArrayEquals(pepper, unsealedBytes,
                        "unsealed pepper must match the sealed original byte-for-byte");
            } finally {
                Arrays.fill(roundTripped, '\0');
            }
        }
    }

    @Test
    void wrongPasswordFailsToUnseal(@TempDir Path dir) throws Exception {
        assumeTrue(simulatorReachable(),
                "TPM simulator not reachable; skipping wrong-password test");

        byte[] pepper = "some-pepper".getBytes();
        Tpm2SealedBlob blob = Tpm2Provisioner.seal(
                pepper, "correct-password".toCharArray(), TpmFactory::localTpmSimulator);
        Path blobPath = dir.resolve("p.tpm2blob");
        blob.writeTo(blobPath);

        assertThrows(IOException.class,
                () -> Tpm2KeyMaterialProvider.forSimulator(blobPath, "WRONG".toCharArray()),
                "wrong password must fail the TPM unseal authorisation as a checked IOException");
    }
}
