package de.swiesend.secretservice.hardened.tpm2;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tss.Tpm;
import tss.TpmFactory;
import tss.tpm.TPM2B_PRIVATE;
import tss.tpm.TPM2B_PUBLIC;
import tss.tpm.TPM2B_PUBLIC_KEY_RSA;
import tss.tpm.TPMA_OBJECT;
import tss.tpm.TPMS_NULL_ASYM_SCHEME;
import tss.tpm.TPMS_RSA_PARMS;
import tss.tpm.TPMS_SENSITIVE_CREATE;
import tss.tpm.TPMS_PCR_SELECTION;
import tss.tpm.TPMT_PUBLIC;
import tss.tpm.TPMT_SYM_DEF_OBJECT;
import tss.tpm.TPM_ALG_ID;
import tss.tpm.TPM_HANDLE;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * {@link KeyMaterialProvider} whose pepper is sealed inside a TPM 2.0.
 *
 * <p>At rest on disk, the pepper is never plaintext and never an env var.
 * Recovering it requires:</p>
 * <ol>
 *   <li>The TPM that produced the sealed blob (non-migratable).</li>
 *   <li>The policy secret -- today, a password supplied at construction.</li>
 * </ol>
 *
 * <p>Constructor behaviour:</p>
 * <ol>
 *   <li>Open a connection to the TPM (platform device or simulator).</li>
 *   <li>{@code TPM2_CreatePrimary} a transient storage-root RSA key under
 *       {@code TPM_RH_OWNER} with an empty owner-auth (the default on most
 *       Linux boxes; operators with owner-auth set override via the supplier).</li>
 *   <li>{@code TPM2_Load} the sealed keyed-hash blob from {@link Tpm2SealedBlob}.</li>
 *   <li>{@code TPM2_Unseal} after attaching the password as the handle's auth value.</li>
 *   <li>Cache the resulting bytes as a {@code char[]} internal to this instance;
 *       flush transient contexts; close the TPM connection.</li>
 * </ol>
 *
 * <p>{@link #getPepper()} returns a <b>clone</b> of the cached value; callers
 * are expected to zero their copy (the {@code HardenedCollection} finally
 * block does this). {@link #close()} zeroes the internal cache.</p>
 *
 * <h3>Threat coverage (honest)</h3>
 * <p>This provider reports {@code sameUid=PARTIAL} in its
 * {@link ThreatCoverage}. The TPM authenticates possession of a secret (the
 * password) and platform state (PCR), not the identity of the caller: a
 * same-UID attacker opens {@code /dev/tpmrm0} and speaks TPM 2.0 directly, or
 * ptraces the JVM and reads the already-unsealed pepper out of the heap.
 * Meaningful same-UID defense requires an external MAC policy (SELinux label,
 * AppArmor profile, or systemd {@code DeviceAllow}/{@code PrivateDevices})
 * restricting {@code /dev/tpmrm0} access to the legitimate binary. The
 * {@code HardenedCollection.Builder} still accepts this provider without
 * {@code acknowledgeSecurityTheater(true)} because {@code PARTIAL} is not the
 * builder's {@code NONE}-gated theater rating -- but deployers should pair it
 * with a MAC policy for real same-UID protection.</p>
 *
 * <p>The TPM does give genuine defense against offline disk thieves (the
 * blob is useless without the TPM) and cross-UID readers (device-node
 * permissions), both of which stay rated {@code REAL}.</p>
 */
public final class Tpm2KeyMaterialProvider implements KeyMaterialProvider, AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(Tpm2KeyMaterialProvider.class);

    private final char[] cachedPepper;
    private volatile boolean closed = false;

    /** Create the provider against the platform TPM (Linux {@code /dev/tpm*} / Windows TBS). */
    public static Tpm2KeyMaterialProvider forPlatformTpm(Path blobPath, char[] password) throws IOException {
        return new Tpm2KeyMaterialProvider(blobPath, password, TpmFactory::platformTpm);
    }

    /** Create against a TPM simulator on {@code localhost:2321} (for tests / CI). */
    public static Tpm2KeyMaterialProvider forSimulator(Path blobPath, char[] password) throws IOException {
        return new Tpm2KeyMaterialProvider(blobPath, password, TpmFactory::localTpmSimulator);
    }

    /**
     * General constructor: supplier returns a connected {@link Tpm} that the provider closes.
     *
     * <p>Throws {@link IOException} on any failure path: filesystem errors reading
     * the sealed-blob file, unsupported policy kinds, TPM transport failures, and
     * TPM error codes (wrong password, lockout, missing device). TSS.Java's
     * unchecked exceptions are caught and wrapped so callers can rely on a single
     * checked exception type.</p>
     */
    public Tpm2KeyMaterialProvider(Path blobPath, char[] password, Supplier<Tpm> tpmSupplier) throws IOException {
        Objects.requireNonNull(blobPath, "blobPath");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(tpmSupplier, "tpmSupplier");
        Tpm2SealedBlob blob = Tpm2SealedBlob.readFrom(blobPath);
        if (blob.policyKind() != Tpm2SealedBlob.PolicyKind.PASSWORD) {
            throw new IOException("unsupported policyKind for this provider: " + blob.policyKind()
                    + " (only PASSWORD is implemented in v1)");
        }
        byte[] pepperBytes;
        try {
            pepperBytes = unseal(blob, password, tpmSupplier);
        } catch (RuntimeException e) {
            // TSS.Java throws unchecked on TPM error codes / transport failures; wrap so
            // the constructor's declared IOException contract covers every failure mode.
            throw new IOException("TPM unseal failed: " + e.getMessage(), e);
        }
        try {
            this.cachedPepper = utf8ToChars(pepperBytes);
        } finally {
            Arrays.fill(pepperBytes, (byte) 0);
        }
    }

    @Override
    public char[] getPepper() {
        if (closed) throw new IllegalStateException("provider closed");
        return cachedPepper.clone();
    }

    @Override
    public Optional<byte[]> getTotpSeed() { return Optional.empty(); }

    @Override
    public Mode mode() { return Mode.NO_TOTP; }

    @Override
    public ThreatCoverage threatCoverage() {
        return new ThreatCoverage(
                // Same-UID is PARTIAL, not REAL: the TPM authenticates POSSESSION OF A SECRET
                // (the password) and PLATFORM STATE (PCR), not the identity of the caller. A
                // same-UID attacker on the same host opens /dev/tpmrm0 and speaks TPM 2.0
                // directly, or ptraces this JVM and reads the already-unsealed pepper out of
                // the heap. Meaningful same-UID defense requires an external MAC policy
                // (SELinux label, AppArmor profile, or systemd DeviceAllow / PrivateDevices)
                // that restricts /dev/tpmrm0 access to the legitimate binary.
                ThreatCoverage.Level.PARTIAL,
                ThreatCoverage.Level.REAL,
                ThreatCoverage.Level.REAL,
                ThreatCoverage.Level.NOT_APPLICABLE,
                "Pepper sealed inside TPM 2.0 under password policy. Same-UID defense requires "
                        + "an external MAC policy (SELinux label, AppArmor profile, or systemd "
                        + "DeviceAllow) restricting /dev/tpmrm0 access to this binary. Without "
                        + "that, a same-UID attacker reads the unsealed pepper from JVM memory "
                        + "or issues TPM commands directly. The TPM defends against offline "
                        + "theft (blob is useless without the TPM) and cross-UID readers "
                        + "(device node permissions); it does not mediate same-UID callers."
        );
    }

    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(cachedPepper, '\0');
            closed = true;
        }
    }

    // ---------- TPM I/O ----------

    private static byte[] unseal(Tpm2SealedBlob blob, char[] password, Supplier<Tpm> tpmSupplier) {
        byte[] authValue = charsToUtf8(password);
        Tpm tpm = null;
        TPM_HANDLE primary = null;
        TPM_HANDLE sealed = null;
        try {
            tpm = tpmSupplier.get();
            primary = tpm.CreatePrimary(
                    tpm._OwnerHandle,
                    new TPMS_SENSITIVE_CREATE(new byte[0], new byte[0]),
                    storageRootTemplate(),
                    new byte[0],
                    new TPMS_PCR_SELECTION[0]).handle;

            TPM2B_PUBLIC outPublic = TPM2B_PUBLIC.fromBytes(blob.outPublic());
            TPM2B_PRIVATE outPrivate = TPM2B_PRIVATE.fromBytes(blob.outPrivate());
            sealed = tpm.Load(primary, outPrivate, outPublic.publicArea);
            sealed.AuthValue = authValue;

            return tpm.Unseal(sealed);
        } finally {
            if (tpm != null) {
                try {
                    if (sealed != null) tpm.FlushContext(sealed);
                } catch (RuntimeException e) {
                    log.warn("FlushContext(sealed) failed; transient TPM handle may leak until TPM reset: {}",
                            e.toString());
                }
                try {
                    if (primary != null) tpm.FlushContext(primary);
                } catch (RuntimeException e) {
                    log.warn("FlushContext(primary) failed; transient TPM handle may leak until TPM reset: {}",
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
     * RSA-2048 storage-root template. Matches the "standard" TPM owner-hierarchy
     * primary key used by tpm2-tools and tpm2-pkcs11 except that this template
     * omits {@code TPMA_OBJECT.noDA}. That matches the non-{@code noDA} posture
     * of the leaf seal template in {@link Tpm2Provisioner}; the primary itself
     * is transient and never authenticates via a password (owner-auth is empty
     * in the constructor path), so the flag is effectively a no-op on the primary
     * -- but removing it keeps the policy posture consistent across both templates.
     */
    static TPMT_PUBLIC storageRootTemplate() {
        return new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.decrypt, TPMA_OBJECT.fixedTPM,
                        TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin,
                        TPMA_OBJECT.userWithAuth),
                new byte[0],
                new TPMS_RSA_PARMS(
                        new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
                        new TPMS_NULL_ASYM_SCHEME(), 2048, 0),
                new TPM2B_PUBLIC_KEY_RSA(new byte[0]));
    }

    // ---------- encoding helpers ----------

    private static byte[] charsToUtf8(char[] chars) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] out = new byte[encoded.remaining()];
        encoded.get(out);
        if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
        return out;
    }

    private static char[] utf8ToChars(byte[] bytes) {
        CharBuffer cb = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
        char[] out = new char[cb.remaining()];
        cb.get(out);
        if (cb.hasArray()) Arrays.fill(cb.array(), '\0');
        return out;
    }
}
