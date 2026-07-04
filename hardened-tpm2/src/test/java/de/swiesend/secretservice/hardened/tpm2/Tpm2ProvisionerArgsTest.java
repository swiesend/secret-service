package de.swiesend.secretservice.hardened.tpm2;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Argument-parser + pepper-source tests for {@link Tpm2Provisioner}. None of these tests
 * require a TPM simulator; they exercise pure CLI plumbing.
 */
class Tpm2ProvisionerArgsTest {

    @Test
    void defaultPepperIsRawEntropyAndBase64FormIsUtf8Safe() throws Exception {
        // The default pepper source now returns 32 raw bytes of entropy; seal() owns the base64
        // encoding that makes the pepper binary-safe (audit F-9). Verify the source yields raw
        // entropy and that its base64 form (what gets sealed) round-trips losslessly through UTF-8.
        Tpm2Provisioner.Args args = Tpm2Provisioner.Args.parse(new String[]{
                "--out", "/tmp/ignored", "--password-env", "PW"
        });
        byte[] pepper = args.pepperSource.read();
        try {
            assertEquals(32, pepper.length, "default pepper should be 32 bytes of raw entropy");
            byte[] sealable = Base64.getEncoder().encode(pepper); // what seal() will store
            String s = new String(sealable, StandardCharsets.UTF_8);
            byte[] reencoded = s.getBytes(StandardCharsets.UTF_8);
            assertEquals(sealable.length, reencoded.length);
            for (int i = 0; i < sealable.length; i++) {
                assertEquals(sealable[i], reencoded[i],
                        "sealed base64 pepper must round-trip losslessly through UTF-8 (index " + i + ")");
            }
            assertNotNull(Base64.getDecoder().decode(s));
        } finally {
            java.util.Arrays.fill(pepper, (byte) 0);
        }
    }

    @Test
    void defaultPepperIsFreshOnEachCall() throws Exception {
        // Each provisioning run produces a fresh pepper; .read() must not be a constant.
        Tpm2Provisioner.PepperSource src = Tpm2Provisioner.randomPepperSource();
        byte[] a = src.read();
        byte[] b = src.read();
        try {
            assertNotEquals(java.util.Base64.getEncoder().encodeToString(a),
                            java.util.Base64.getEncoder().encodeToString(b),
                    "two consecutive random peppers must differ");
        } finally {
            java.util.Arrays.fill(a, (byte) 0);
            java.util.Arrays.fill(b, (byte) 0);
        }
    }

    @Test
    void pepperEnvSourceReadsExactBytes() throws Exception {
        // We can't set env vars from a unit test portably; exercise the underlying source
        // logic via the explicit factory method against a known var.
        String existing = System.getenv("PATH");
        if (existing == null || existing.isEmpty()) return; // skip on minimal envs
        Tpm2Provisioner.PepperSource src = Tpm2Provisioner.pepperEnvSource("PATH");
        byte[] read = src.read();
        try {
            assertEquals(existing, new String(read, StandardCharsets.UTF_8),
                    "pepperEnvSource must return the env var verbatim");
        } finally {
            java.util.Arrays.fill(read, (byte) 0);
        }
    }

    @Test
    void parseRejectsBothPasswordAndPepperOnStdin() {
        // The classic conflict: only one consumer can read from fd 0.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                Tpm2Provisioner.Args.parse(new String[]{
                        "--out", "/tmp/x", "--password-stdin", "--pepper-stdin"
                }));
        assertTrue(e.getMessage().contains("stdin"),
                "error must name the stdin conflict; got: " + e.getMessage());
    }

    @Test
    void parseRejectsBothPasswordFd0AndPepperStdin() {
        // --password-fd 0 is just stdin under another spelling; same conflict.
        assertThrows(IllegalArgumentException.class, () ->
                Tpm2Provisioner.Args.parse(new String[]{
                        "--out", "/tmp/x", "--password-fd", "0", "--pepper-stdin"
                }));
    }

    @Test
    void parseAcceptsPepperEnvWithPasswordStdin() throws Exception {
        // Different sources for password and pepper -- no conflict.
        Tpm2Provisioner.Args args = Tpm2Provisioner.Args.parse(new String[]{
                "--out", "/tmp/x",
                "--password-stdin",
                "--pepper-env", "HOME"   // any always-set env var
        });
        assertNotNull(args.pepperSource);
        assertNotNull(args.passwordSource);
    }

    @Test
    void parseRejectsTwoPepperSources() {
        assertThrows(IllegalArgumentException.class, () ->
                Tpm2Provisioner.Args.parse(new String[]{
                        "--out", "/tmp/x", "--password-env", "PW",
                        "--pepper-env", "PEPPER", "--pepper-stdin"
                }));
    }

    @Test
    void parseRejectsMissingArgValue() {
        // --pepper-env without a var name
        assertThrows(IllegalArgumentException.class, () ->
                Tpm2Provisioner.Args.parse(new String[]{
                        "--out", "/tmp/x", "--password-env", "PW", "--pepper-env"
                }));
        // --pepper-fd with non-integer
        assertThrows(IllegalArgumentException.class, () ->
                Tpm2Provisioner.Args.parse(new String[]{
                        "--out", "/tmp/x", "--password-env", "PW", "--pepper-fd", "abc"
                }));
    }
}
