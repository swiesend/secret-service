package de.swiesend.secretservice.hardened.tpm2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tss.Tpm;
import tss.TpmFactory;
import tss.tpm.CreatePrimaryResponse;
import tss.tpm.CreateResponse;
import tss.tpm.TPMA_OBJECT;
import tss.tpm.TPMS_KEYEDHASH_PARMS;
import tss.tpm.TPMS_NULL_SCHEME_KEYEDHASH;
import tss.tpm.TPMS_SENSITIVE_CREATE;
import tss.tpm.TPMS_PCR_SELECTION;
import tss.tpm.TPM2B_DIGEST_KEYEDHASH;
import tss.tpm.TPM2B_PUBLIC;
import tss.tpm.TPMT_PUBLIC;
import tss.tpm.TPM_ALG_ID;
import tss.tpm.TPM_HANDLE;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Supplier;

/**
 * One-shot operator tool: generates a random pepper, seals it inside the TPM
 * under a password policy, and writes the sealed blob to disk. Run once per
 * TPM/host/installation; the resulting {@code pepper.tpm2blob} is then consumed
 * by {@link Tpm2KeyMaterialProvider} at runtime.
 *
 * <p>CLI usage:</p>
 * <pre>
 * java -cp ... de.swiesend.secretservice.hardened.tpm2.Tpm2Provisioner \
 *      --out ~/.config/secret-service/hardened/pepper.tpm2blob \
 *      --password "correct horse battery staple" \
 *      [--simulator]
 * </pre>
 *
 * <p>The plaintext pepper is zeroed in memory immediately after sealing. The
 * only artefact on disk is the TPM-wrapped blob; losing the TPM or the password
 * renders the blob unopenable (by design).</p>
 */
public final class Tpm2Provisioner {

    private static final Logger log = LoggerFactory.getLogger(Tpm2Provisioner.class);

    private Tpm2Provisioner() {}

    public static void main(String[] args) throws Exception {
        Args parsed = Args.parse(args);
        if (parsed == null) {
            usage(System.err);
            System.exit(2);
        }
        Supplier<Tpm> tpmSupplier = parsed.simulator ? TpmFactory::localTpmSimulator : TpmFactory::platformTpm;
        byte[] pepper = new byte[32];
        new SecureRandom().nextBytes(pepper);
        try {
            Tpm2SealedBlob blob = seal(pepper, parsed.password, tpmSupplier);
            blob.writeTo(parsed.outputPath);
            System.out.println("wrote sealed blob to " + parsed.outputPath);
        } finally {
            Arrays.fill(pepper, (byte) 0);
            Arrays.fill(parsed.password, '\0');
        }
    }

    /**
     * Seal {@code pepperBytes} under {@code password}. The caller is responsible for
     * zeroing {@code pepperBytes} and {@code password} after this method returns; the
     * method zeroes its internal copies.
     */
    public static Tpm2SealedBlob seal(byte[] pepperBytes, char[] password, Supplier<Tpm> tpmSupplier) {
        byte[] authValue = charsToUtf8(password);
        Tpm tpm = tpmSupplier.get();
        TPM_HANDLE primary = null;
        try {
            CreatePrimaryResponse cpr = tpm.CreatePrimary(
                    tpm._OwnerHandle,
                    new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]),
                    Tpm2KeyMaterialProvider.storageRootTemplate(),
                    new byte[0],
                    new TPMS_PCR_SELECTION[0]);
            primary = cpr.handle;

            CreateResponse cr = tpm.Create(
                    primary,
                    new TPMS_SENSITIVE_CREATE(authValue, pepperBytes),
                    sealTemplate(),
                    new byte[0],
                    new TPMS_PCR_SELECTION[0]);

            byte[] outPublicBytes = new TPM2B_PUBLIC(cr.outPublic).toTpm();
            byte[] outPrivateBytes = cr.outPrivate.toTpm();
            return new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD, outPublicBytes, outPrivateBytes);
        } finally {
            try {
                if (primary != null) tpm.FlushContext(primary);
            } catch (RuntimeException e) {
                log.debug("FlushContext(primary) failed: {}", e.toString());
            }
            try {
                tpm.close();
            } catch (IOException e) {
                log.debug("tpm.close() failed: {}", e.toString());
            }
            Arrays.fill(authValue, (byte) 0);
        }
    }

    /**
     * Sealed keyed-hash template. Note the absence of {@code TPMA_OBJECT.noDA}: the
     * sealed object participates in the TPM's Dictionary Attack (DA) lockout, so a
     * same-UID attacker who captures the blob file but lacks the password cannot
     * brute-force it -- after a small number of failed {@code TPM2_Unseal} attempts
     * (typically 32, operator-configurable via {@code TPM2_DictionaryAttackParameters})
     * the TPM enters lockout and refuses further auth attempts on this object. The
     * legitimate flow supplies the correct password and never trips the counter.
     */
    private static TPMT_PUBLIC sealTemplate() {
        return new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent,
                        TPMA_OBJECT.userWithAuth),
                new byte[0],
                new TPMS_KEYEDHASH_PARMS(new TPMS_NULL_SCHEME_KEYEDHASH()),
                new TPM2B_DIGEST_KEYEDHASH(new byte[0]));
    }

    private static byte[] charsToUtf8(char[] chars) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] out = new byte[encoded.remaining()];
        encoded.get(out);
        if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
        return out;
    }

    private static void usage(PrintStream out) {
        out.println("usage: Tpm2Provisioner --out <path> --password <pw> [--simulator]");
        out.println("  --out         path of the sealed-blob file to create (mode 0600)");
        out.println("  --password    password that gates Tpm2_Unseal at runtime");
        out.println("  --simulator   use localhost:2321 TPM simulator instead of platform TPM");
    }

    static final class Args {
        final Path outputPath;
        final char[] password;
        final boolean simulator;

        Args(Path outputPath, char[] password, boolean simulator) {
            this.outputPath = outputPath;
            this.password = password;
            this.simulator = simulator;
        }

        static Args parse(String[] argv) {
            Path out = null;
            char[] password = null;
            boolean simulator = false;
            for (int i = 0; i < argv.length; i++) {
                String a = argv[i];
                switch (a) {
                    case "--out" -> out = (i + 1 < argv.length) ? Paths.get(argv[++i]) : null;
                    case "--password" -> password = (i + 1 < argv.length) ? argv[++i].toCharArray() : null;
                    case "--simulator" -> simulator = true;
                    default -> { return null; }
                }
            }
            if (out == null || password == null || password.length == 0) return null;
            return new Args(out, password, simulator);
        }
    }
}
