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

import java.io.BufferedReader;
import java.io.Console;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Supplier;

/**
 * One-shot operator tool: generates a random pepper, seals it inside the TPM
 * under a password policy, and writes the sealed blob to disk. Run once per
 * TPM/host/installation; the resulting {@code pepper.tpm2blob} is then consumed
 * by {@link Tpm2KeyMaterialProvider} at runtime.
 *
 * <h2>CLI usage</h2>
 * <pre>
 * java -cp ... de.swiesend.secretservice.hardened.tpm2.Tpm2Provisioner \
 *      --out ~/.config/secret-service/hardened/pepper.tpm2blob \
 *      --password-stdin \
 *      [--simulator]
 * </pre>
 *
 * <p>Exactly one password-source flag is required:</p>
 * <ul>
 *   <li>{@code --password-stdin} -- read one line (LF- or CRLF-terminated) from stdin.
 *       The terminator is stripped. This is the recommended CI pattern
 *       ({@code echo "$PW" | tpm2-provisioner ...}).</li>
 *   <li>{@code --password-env VAR} -- read from the named environment variable.
 *       The caller is responsible for unsetting it after invocation.</li>
 *   <li>{@code --password-fd N} -- read from file descriptor {@code N}. Useful in
 *       shell redirection ({@code tpm2-provisioner --password-fd 3 3<<<"$PW"}).</li>
 *   <li>{@code --password-prompt} -- prompt interactively with echoing disabled
 *       via {@link Console#readPassword}. Default when none of the above is given
 *       <i>and</i> a controlling tty is attached.</li>
 * </ul>
 *
 * <p>The old {@code --password <plaintext>} flag has been removed: it leaked the
 * password into {@code /proc/<pid>/cmdline}, {@code ps} output, shell history,
 * and audit logs. There is no safe way to accept a password as a command-line
 * argument, so the option is simply gone.</p>
 *
 * <p>After sealing, the in-process pepper and password buffers are zeroed.
 * The only artefact on disk is the TPM-wrapped blob; losing the TPM or the
 * password renders the blob unopenable (by design).</p>
 */
public final class Tpm2Provisioner {

    private static final Logger log = LoggerFactory.getLogger(Tpm2Provisioner.class);

    private Tpm2Provisioner() {}

    public static void main(String[] args) {
        Args parsed;
        try {
            parsed = Args.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("tpm2-provisioner: " + e.getMessage());
            usage(System.err);
            System.exit(2);
            return;
        }

        char[] password = null;
        byte[] pepper = new byte[32];
        try {
            password = parsed.passwordSource.read();
            if (password.length == 0) {
                System.err.println("tpm2-provisioner: password is empty");
                System.exit(2);
                return;
            }
            Supplier<Tpm> tpmSupplier = parsed.simulator
                    ? TpmFactory::localTpmSimulator
                    : TpmFactory::platformTpm;
            new SecureRandom().nextBytes(pepper);
            Tpm2SealedBlob blob = seal(pepper, password, tpmSupplier);
            blob.writeTo(parsed.outputPath);
            System.out.println("wrote sealed blob to " + parsed.outputPath);
        } catch (IOException e) {
            System.err.println("tpm2-provisioner: I/O error: " + e.getMessage());
            System.exit(3);
        } catch (RuntimeException e) {
            // TSS.Java throws unchecked on TPM error codes / transport failures
            System.err.println("tpm2-provisioner: TPM error: " + e.getMessage());
            System.exit(4);
        } finally {
            Arrays.fill(pepper, (byte) 0);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /**
     * Seal {@code pepperBytes} under {@code password}. The caller is responsible for
     * zeroing {@code pepperBytes} and {@code password} after this method returns; the
     * method zeroes its internal copies.
     */
    public static Tpm2SealedBlob seal(byte[] pepperBytes, char[] password, Supplier<Tpm> tpmSupplier) {
        byte[] authValue = charsToUtf8(password);
        Tpm tpm = null;
        TPM_HANDLE primary = null;
        try {
            tpm = tpmSupplier.get();
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
            if (tpm != null) {
                try {
                    if (primary != null) tpm.FlushContext(primary);
                } catch (RuntimeException e) {
                    log.warn("FlushContext(primary) failed during seal; transient handle may leak until TPM reset: {}",
                            e.toString());
                }
                try {
                    tpm.close();
                } catch (IOException e) {
                    log.debug("tpm.close() failed: {}", e.toString());
                }
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
        out.println("usage: Tpm2Provisioner --out <path> [password-source] [--simulator]");
        out.println("  --out               path of the sealed-blob file to create (mode 0600)");
        out.println("  --simulator         use localhost:2321 TPM simulator instead of platform TPM");
        out.println();
        out.println("password source (exactly one; --password-prompt is the default on a tty):");
        out.println("  --password-stdin    read one line from stdin");
        out.println("  --password-env VAR  read from environment variable VAR");
        out.println("  --password-fd N     read one line from file descriptor N");
        out.println("  --password-prompt   interactive, echoing disabled via java.io.Console");
    }

    // ---------- password source plumbing ----------

    /** A pluggable way to obtain the unseal password, returning a fresh char[]. */
    @FunctionalInterface
    interface PasswordSource {
        char[] read() throws IOException;
    }

    static PasswordSource stdinSource() {
        return () -> readLineChars(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    }

    static PasswordSource envSource(String varName) {
        return () -> {
            String val = System.getenv(varName);
            if (val == null) throw new IOException("env var " + varName + " is unset");
            return val.toCharArray();
        };
    }

    static PasswordSource fdSource(int fd) {
        return () -> {
            // Note: Java has no public API for "give me a FileDescriptor for fd N" beyond
            // FileDescriptor.in/out/err. For non-standard fds, read via /dev/fd/N on
            // Linux. Falls back to stdin when N==0.
            if (fd == 0) return readLineChars(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            Path fdPath = Path.of("/dev/fd/" + fd);
            try (var reader = new FileReader(fdPath.toFile(), StandardCharsets.UTF_8)) {
                return readLineChars(reader);
            }
        };
    }

    static PasswordSource promptSource() {
        return () -> {
            Console console = System.console();
            if (console == null) {
                throw new IOException("no controlling tty; use --password-stdin / --password-env / --password-fd");
            }
            char[] pw = console.readPassword("TPM unseal password: ");
            if (pw == null) throw new IOException("stdin closed before password was entered");
            return pw;
        };
    }

    private static char[] readLineChars(java.io.Reader reader) throws IOException {
        BufferedReader br = new BufferedReader(reader);
        String line = br.readLine();
        if (line == null) throw new IOException("empty input; no password line available");
        // strip trailing CR that BufferedReader leaves on CRLF input in some edge cases
        int len = line.length();
        if (len > 0 && line.charAt(len - 1) == '\r') line = line.substring(0, len - 1);
        return line.toCharArray();
    }

    // ---------- argv parsing ----------

    static final class Args {
        final Path outputPath;
        final PasswordSource passwordSource;
        final boolean simulator;

        Args(Path outputPath, PasswordSource passwordSource, boolean simulator) {
            this.outputPath = outputPath;
            this.passwordSource = passwordSource;
            this.simulator = simulator;
        }

        static Args parse(String[] argv) {
            Path out = null;
            PasswordSource pwSource = null;
            boolean simulator = false;
            int sourcesSpecified = 0;
            for (int i = 0; i < argv.length; i++) {
                String a = argv[i];
                switch (a) {
                    case "--out" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--out requires a path argument");
                        out = Path.of(argv[i]);
                    }
                    case "--password-stdin" -> { pwSource = stdinSource(); sourcesSpecified++; }
                    case "--password-env" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--password-env requires a var name");
                        pwSource = envSource(argv[i]);
                        sourcesSpecified++;
                    }
                    case "--password-fd" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--password-fd requires an integer");
                        int fd;
                        try { fd = Integer.parseInt(argv[i]); }
                        catch (NumberFormatException e) {
                            throw new IllegalArgumentException("--password-fd must be an integer, got: " + argv[i]);
                        }
                        pwSource = fdSource(fd);
                        sourcesSpecified++;
                    }
                    case "--password-prompt" -> { pwSource = promptSource(); sourcesSpecified++; }
                    case "--simulator" -> simulator = true;
                    default -> throw new IllegalArgumentException("unknown flag: " + a);
                }
            }
            if (out == null) throw new IllegalArgumentException("--out is required");
            if (sourcesSpecified > 1) {
                throw new IllegalArgumentException("specify at most one password source");
            }
            if (pwSource == null) {
                // Default to interactive prompt; at read() time this fails closed if no tty.
                pwSource = promptSource();
            }
            return new Args(out, pwSource, simulator);
        }
    }
}
