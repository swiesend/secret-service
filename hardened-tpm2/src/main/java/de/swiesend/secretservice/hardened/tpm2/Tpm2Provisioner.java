package de.swiesend.secretservice.hardened.tpm2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tss.Tpm;
import tss.TpmFactory;
import tss.tpm.CreatePrimaryResponse;
import tss.tpm.CreateResponse;
import tss.tpm.TPMA_OBJECT;
import tss.tpm.TPMA_NV;
import tss.tpm.TPMS_KEYEDHASH_PARMS;
import tss.tpm.TPMS_NULL_SCHEME_KEYEDHASH;
import tss.tpm.TPMS_NV_PUBLIC;
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
 * <p>By default the tool generates a fresh base64-encoded ASCII pepper internally
 * (32 bytes of {@link SecureRandom} → ~44 ASCII chars). Operators who need to
 * cross-host-escrow the pepper (so that re-provisioning on a different TPM still
 * yields the same {@code KeyMaterialProvider#getPepper()} char sequence) can
 * supply their own pepper via one of:</p>
 *
 * <ul>
 *   <li>{@code --pepper-stdin} — read one line from stdin (mutually exclusive with
 *       {@code --password-stdin}).</li>
 *   <li>{@code --pepper-env VAR} — read from environment variable {@code VAR}.</li>
 *   <li>{@code --pepper-fd N} — read one line from file descriptor {@code N}.</li>
 * </ul>
 *
 * <p><b>The sealed pepper is base64-encoded, not verbatim.</b> {@link #seal} encodes the
 * supplied bytes, so {@code Tpm2KeyMaterialProvider.getPepper()} returns
 * {@code base64(pepperBytes)} — not the bytes the operator passed in. This matters for
 * the cross-host escrow the {@code --pepper-*} options exist for: the two providers must
 * hand the DEK derivation the <em>same</em> value, and they transform their input
 * differently. This provider returns {@code base64(P)}; {@code FileKeyMaterialProvider}
 * base64-<em>decodes</em> its line before returning it. So a file line of
 * {@code base64(P)} yields {@code P} -- one hop short -- and every item written on the
 * other host fails AEAD authentication, reported as tampering. To pair the two, the
 * escrow file line must be {@code base64(base64(P))}, i.e. the base64 encoding of the
 * exact value this provider returns. The less error-prone route is to skip the pairing
 * entirely: seal on every host from the same source bytes with {@code --pepper-file},
 * so each host runs this provider and no cross-provider transform is involved. Pepper
 * round-trip uses UTF-8, so caller-supplied input must be valid UTF-8 text — typically
 * ASCII (a base64 random pepper from {@code openssl rand -base64 32} works perfectly).</p>
 *
 * <p>After sealing, the in-process pepper and password buffers are zeroed.
 * The only artefact on disk is the TPM-wrapped blob; losing the TPM or the
 * password renders the blob unopenable (by design).</p>
 */
public final class Tpm2Provisioner {

    private static final Logger log = LoggerFactory.getLogger(Tpm2Provisioner.class);

    private Tpm2Provisioner() {}

    public static void main(String[] args) {
        // System.exit only HERE, never inside run(): exit() terminates the JVM without running
        // finally blocks, so an exit inside run()'s try skipped the zeroing of the password and
        // pepper -- on the realistic failure paths (I/O error, TPM error) they were already in
        // memory. run() returns the code instead; every path passes through its finally first.
        System.exit(run(args));
    }

    /** The CLI body; package-private so the exit-code contract is testable without forking a JVM. */
    static int run(String[] args) {
        Args parsed;
        try {
            parsed = Args.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("tpm2-provisioner: " + e.getMessage());
            usage(System.err);
            return 2;
        }

        char[] password = null;
        byte[] pepper = null;
        try {
            password = parsed.passwordSource.read();
            if (password.length == 0) {
                System.err.println("tpm2-provisioner: password is empty");
                return 2;
            }
            Supplier<Tpm> tpmSupplier = parsed.simulator
                    ? TpmFactory::localTpmSimulator
                    : TpmFactory::platformTpm;

            if (parsed.defineCounterIndex != null) {
                defineGenerationCounter(parsed.defineCounterIndex, password, tpmSupplier);
                System.out.println("defined NV generation counter at index 0x"
                        + Integer.toHexString(parsed.defineCounterIndex));
                return 0;
            }

            pepper = parsed.pepperSource.read();
            if (pepper.length == 0) {
                System.err.println("tpm2-provisioner: pepper is empty");
                return 2;
            }
            Tpm2SealedBlob blob = seal(pepper, password, tpmSupplier);
            blob.writeTo(parsed.outputPath);
            System.out.println("wrote sealed blob to " + parsed.outputPath);
            return 0;
        } catch (IOException e) {
            System.err.println("tpm2-provisioner: I/O error: " + e.getMessage());
            return 3;
        } catch (RuntimeException e) {
            // TSS.Java throws unchecked on TPM error codes / transport failures
            System.err.println("tpm2-provisioner: TPM error: " + e.getMessage());
            return 4;
        } finally {
            if (pepper != null) Arrays.fill(pepper, (byte) 0);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /**
     * Seal {@code pepperBytes} under {@code password}. The caller is responsible for
     * zeroing {@code pepperBytes} and {@code password} after this method returns; the
     * method zeroes its internal copies.
     *
     * <p>The pepper is base64-encoded before sealing so that <b>any</b> input bytes round-trip
     * losslessly through the text-oriented pepper SPI ({@code getPepper()} returns a {@code char[]}
     * and {@code HardenedCollection} re-encodes it as UTF-8). Callers therefore pass raw entropy;
     * the seal owns the encoding. The provider's effective pepper is {@code base64(pepperBytes)}.
     * This produces a v2 {@link Tpm2SealedBlob}; older v1 blobs (verbatim, not binary-safe) are
     * rejected on read and must be re-provisioned.</p>
     */
    public static Tpm2SealedBlob seal(byte[] pepperBytes, char[] password, Supplier<Tpm> tpmSupplier) {
        byte[] authValue = charsToUtf8(password);
        // Base64 the pepper so non-UTF-8 input survives the char[]/UTF-8 round-trip (audit F-9).
        byte[] sealable = java.util.Base64.getEncoder().encode(pepperBytes);
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
                    new TPMS_SENSITIVE_CREATE(authValue, sealable),
                    sealTemplate(),
                    new byte[0],
                    new TPMS_PCR_SELECTION[0]);

            byte[] outPublicBytes = new TPM2B_PUBLIC(cr.outPublic).toTpm();
            byte[] outPrivateBytes = cr.outPrivate.toTpm();
            return new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD, outPublicBytes, outPrivateBytes);
        } finally {
            Arrays.fill(sealable, (byte) 0);
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
     * Define a TPM NV <b>monotonic counter</b> to back {@link Tpm2GenerationAnchor}. Run once per
     * collection/keystore, at a distinct {@code nvIndex}. The counter is created under the owner
     * hierarchy with the given {@code password} as its index auth value (increment and read are
     * auth-gated so a hostile process cannot drive the floor), and is initialised with one
     * increment so it is immediately readable.
     *
     * <p>Increment/read auth participates in the TPM dictionary-attack lockout ({@code NO_DA} is
     * deliberately not set). The caller zeroes {@code password}; this method zeroes its copy.</p>
     *
     * @throws RuntimeException (TSS.Java unchecked) if the index is already defined or the TPM
     *         rejects the definition.
     */
    public static void defineGenerationCounter(int nvIndex, char[] password, Supplier<Tpm> tpmSupplier) {
        byte[] auth = charsToUtf8(password);
        Tpm tpm = null;
        try {
            tpm = tpmSupplier.get();
            // nvIndex is a full NV handle (e.g. 0x01800200). Construct it directly: TPM_HANDLE.NV(x)
            // adds the NV base 0x01000000 to x, so passing a full handle overflows into the
            // handle-type byte (0x01800200 -> 0x02800200) and the TPM rejects it with TPM_RC_VALUE.
            TPM_HANDLE idx = new TPM_HANDLE(nvIndex);
            TPMS_NV_PUBLIC nvPublic = new TPMS_NV_PUBLIC(
                    idx,
                    TPM_ALG_ID.SHA256,
                    new TPMA_NV(TPMA_NV.COUNTER, TPMA_NV.AUTHWRITE, TPMA_NV.AUTHREAD),
                    new byte[0], // no policy; auth is the index auth value
                    8);          // TPM NV counters are 8 bytes
            tpm.NV_DefineSpace(tpm._OwnerHandle, auth, nvPublic);
            // First increment initialises the counter so NV_Read succeeds thereafter.
            idx.AuthValue = auth;
            tpm.NV_Increment(idx, idx);
        } finally {
            if (tpm != null) {
                try {
                    tpm.close();
                } catch (IOException e) {
                    log.debug("tpm.close() failed: {}", e.toString());
                }
            }
            Arrays.fill(auth, (byte) 0);
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
        out.println("usage: Tpm2Provisioner --out <path> [password-source] [pepper-source] [--simulator]");
        out.println("   or: Tpm2Provisioner --define-counter <nv-index> [password-source] [--simulator]");
        out.println("  --out               path of the sealed-blob file to create (mode 0600)");
        out.println("  --define-counter I  define an NV monotonic counter at index I (e.g. 0x01800200)");
        out.println("                      to back Tpm2GenerationAnchor, instead of sealing a pepper");
        out.println("  --simulator         use localhost:2321 TPM simulator instead of platform TPM");
        out.println();
        out.println("password source (exactly one; --password-prompt is the default on a tty):");
        out.println("  --password-stdin    read one line from stdin");
        out.println("  --password-env VAR  read from environment variable VAR");
        out.println("  --password-fd N     read one line from file descriptor N");
        out.println("  --password-prompt   interactive, echoing disabled via java.io.Console");
        out.println();
        out.println("pepper source (default: base64-encoded 32-byte SecureRandom):");
        out.println("  --pepper-stdin      read one line from stdin (conflicts with --password-stdin)");
        out.println("  --pepper-env VAR    read from environment variable VAR");
        out.println("  --pepper-fd N       read one line from file descriptor N");
        out.println();
        out.println("(operator-supplied pepper enables cross-host escrow; default random pepper is");
        out.println(" generated in the JVM and not visible outside the sealed blob.)");
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

    // ---------- pepper source plumbing ----------

    /** Source of pepper bytes that get sealed into the TPM. */
    @FunctionalInterface
    interface PepperSource {
        byte[] read() throws IOException;
    }

    /**
     * Default pepper: 32 raw bytes of {@link SecureRandom} entropy. {@link #seal} base64-encodes
     * whatever bytes it is given before sealing, so the source no longer needs to pre-encode --
     * doing so here too would double-encode. Binary-safety for every pepper source now lives in
     * {@code seal}, not in the individual sources.
     */
    static PepperSource randomPepperSource() {
        return () -> {
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            return raw;
        };
    }

    static PepperSource pepperStdinSource() {
        return () -> readLineUtf8Bytes(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    }

    static PepperSource pepperEnvSource(String varName) {
        return () -> {
            String val = System.getenv(varName);
            if (val == null) throw new IOException("env var " + varName + " is unset");
            return val.getBytes(StandardCharsets.UTF_8);
        };
    }

    static PepperSource pepperFdSource(int fd) {
        return () -> {
            if (fd == 0) return readLineUtf8Bytes(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            Path fdPath = Path.of("/dev/fd/" + fd);
            try (var reader = new FileReader(fdPath.toFile(), StandardCharsets.UTF_8)) {
                return readLineUtf8Bytes(reader);
            }
        };
    }

    private static byte[] readLineUtf8Bytes(java.io.Reader reader) throws IOException {
        BufferedReader br = new BufferedReader(reader);
        String line = br.readLine();
        if (line == null) throw new IOException("empty input; no pepper line available");
        int len = line.length();
        if (len > 0 && line.charAt(len - 1) == '\r') line = line.substring(0, len - 1);
        return line.getBytes(StandardCharsets.UTF_8);
    }

    // ---------- argv parsing ----------

    static final class Args {
        final Path outputPath;
        final PasswordSource passwordSource;
        final PepperSource pepperSource;
        final boolean simulator;
        /** When non-null, define an NV generation counter at this index instead of sealing a pepper. */
        final Integer defineCounterIndex;

        Args(Path outputPath, PasswordSource passwordSource, PepperSource pepperSource, boolean simulator,
             Integer defineCounterIndex) {
            this.outputPath = outputPath;
            this.passwordSource = passwordSource;
            this.pepperSource = pepperSource;
            this.simulator = simulator;
            this.defineCounterIndex = defineCounterIndex;
        }

        static Args parse(String[] argv) {
            Path out = null;
            PasswordSource pwSource = null;
            PepperSource pepperSource = null;
            boolean passwordOnStdin = false;
            boolean pepperOnStdin = false;
            boolean simulator = false;
            Integer defineCounterIndex = null;
            int pwSourcesSpecified = 0;
            int pepperSourcesSpecified = 0;
            for (int i = 0; i < argv.length; i++) {
                String a = argv[i];
                switch (a) {
                    case "--out" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--out requires a path argument");
                        out = Path.of(argv[i]);
                    }
                    case "--define-counter" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--define-counter requires an NV index (e.g. 0x01800200)");
                        try { defineCounterIndex = Integer.decode(argv[i]); }
                        catch (NumberFormatException e) {
                            throw new IllegalArgumentException("--define-counter index must be an integer, got: " + argv[i]);
                        }
                    }
                    case "--password-stdin" -> {
                        pwSource = stdinSource();
                        pwSourcesSpecified++;
                        passwordOnStdin = true;
                    }
                    case "--password-env" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--password-env requires a var name");
                        pwSource = envSource(argv[i]);
                        pwSourcesSpecified++;
                    }
                    case "--password-fd" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--password-fd requires an integer");
                        int fd;
                        try { fd = Integer.parseInt(argv[i]); }
                        catch (NumberFormatException e) {
                            throw new IllegalArgumentException("--password-fd must be an integer, got: " + argv[i]);
                        }
                        pwSource = fdSource(fd);
                        pwSourcesSpecified++;
                        if (fd == 0) passwordOnStdin = true;
                    }
                    case "--password-prompt" -> { pwSource = promptSource(); pwSourcesSpecified++; }
                    case "--pepper-stdin" -> {
                        pepperSource = pepperStdinSource();
                        pepperSourcesSpecified++;
                        pepperOnStdin = true;
                    }
                    case "--pepper-env" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--pepper-env requires a var name");
                        pepperSource = pepperEnvSource(argv[i]);
                        pepperSourcesSpecified++;
                    }
                    case "--pepper-fd" -> {
                        if (++i >= argv.length) throw new IllegalArgumentException("--pepper-fd requires an integer");
                        int fd;
                        try { fd = Integer.parseInt(argv[i]); }
                        catch (NumberFormatException e) {
                            throw new IllegalArgumentException("--pepper-fd must be an integer, got: " + argv[i]);
                        }
                        pepperSource = pepperFdSource(fd);
                        pepperSourcesSpecified++;
                        if (fd == 0) pepperOnStdin = true;
                    }
                    case "--simulator" -> simulator = true;
                    default -> throw new IllegalArgumentException("unknown flag: " + a);
                }
            }
            // --define-counter is a distinct action: it needs a password (the counter's index auth)
            // but no --out and no pepper source.
            if (defineCounterIndex == null && out == null) {
                throw new IllegalArgumentException("--out is required (or use --define-counter <index>)");
            }
            if (defineCounterIndex != null && pepperSourcesSpecified > 0) {
                throw new IllegalArgumentException("--define-counter does not seal a pepper; drop the --pepper-* flag");
            }
            if (pwSourcesSpecified > 1) {
                throw new IllegalArgumentException("specify at most one password source");
            }
            if (pepperSourcesSpecified > 1) {
                throw new IllegalArgumentException("specify at most one pepper source");
            }
            if (passwordOnStdin && pepperOnStdin) {
                throw new IllegalArgumentException(
                        "password and pepper cannot both come from stdin (file descriptor 0); "
                                + "use --password-env or --password-fd N for one of them");
            }
            if (pwSource == null) {
                // Default to interactive prompt; at read() time this fails closed if no tty.
                pwSource = promptSource();
            }
            if (pepperSource == null) {
                // Default: tool generates a fresh base64-encoded random pepper. The operator
                // never sees it; pepper recovery requires re-provisioning on the same TPM.
                pepperSource = randomPepperSource();
            }
            return new Args(out, pwSource, pepperSource, simulator, defineCounterIndex);
        }
    }
}
