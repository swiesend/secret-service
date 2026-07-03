package de.swiesend.secretservice.hardened;

import at.favre.lib.hkdf.HKDF;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

/**
 * Application-layer encryption decorator around a {@link CollectionInterface}.
 *
 * <p>On write, the plaintext is encrypted with AES-256-GCM under a per-item DEK derived via
 * HKDF-SHA256 from {pepper, optional TOTP code, per-item salt, epoch id, item id}. The
 * resulting {@link Envelope} (with AEAD ciphertext and tag) is base64-encoded and handed to
 * the wrapped collection as if it were the plaintext. The existing transport encryption
 * then wraps the ciphertext for the D-Bus hop.</p>
 *
 * <p>On read, the envelope is parsed, DEK re-derived from the same factors, plaintext decrypted,
 * and passed to the caller's {@code withSecret} callback. The plaintext {@code char[]} is
 * zeroed in a finally block whether the callback returns or throws.</p>
 *
 * <h3>Non-destructive guarantee</h3>
 * <p>The decorator never reads or modifies pre-existing non-hardened items. An item without
 * the {@code hardened.version} attribute (or without the {@code SSv1} magic in its body) is
 * treated as foreign: {@code withSecret} returns empty and logs a warning; {@code deleteItem}
 * refuses. This protects shared collections — especially the default collection — from
 * accidental data loss.</p>
 *
 * <h3>KEM and forward secrecy</h3>
 * <ul>
 *   <li>Every write uses a KEM against a per-epoch keypair held by the {@link EpochKeystore}:
 *       classical X25519 ({@code kem_id=KEM_ID_X25519}) by default, or X25519+ML-KEM-768
 *       ({@code kem_id=KEM_ID_X25519_MLKEM768}) when {@link Builder#enablePostQuantum(boolean)}
 *       is set and the runtime supplies ML-KEM. The KEM shared secret is mixed into the DEK
 *       alongside the pepper, so the DEK cannot be recovered from the pepper alone.</li>
 *   <li>{@code rotateEpoch} rewraps items under a fresh epoch and then destroys every superseded
 *       epoch keypair. This is real forward secrecy: an envelope snapshotted before rotation can
 *       no longer be decapsulated even by an attacker who later learns the pepper, because the
 *       matching epoch private key is gone.</li>
 *   <li>TOTP {@code STORED_STEP} mode is explicitly labeled theater in {@link HardenedStatus}.
 *       Real time-binding requires {@code LIVE_CODE} mode (write window = read window).</li>
 * </ul>
 */
public final class HardenedCollection implements HardenedCollectionInterface {

    private static final Logger log = LoggerFactory.getLogger(HardenedCollection.class);

    static final String ATTR_VERSION    = "hardened.version";
    static final String ATTR_EPOCH      = "hardened.epoch";
    static final String ATTR_TOTP_MODE  = "hardened.totp.mode";
    static final String ATTR_TOTP_STEP  = "hardened.totp.step";
    static final String ATTR_KDF        = "hardened.kdf";
    static final String ATTR_AEAD       = "hardened.aead";
    static final String ATTR_KEM        = "hardened.kem";
    static final String ATTR_KEM_ID     = "hardened.kem.id";
    static final String ATTR_VERSION_V1 = "1";

    private static final String KDF_ALG   = "hkdf-sha256";
    private static final String AEAD_ALG  = "aes-256-gcm";
    private static final int AEAD_KEY_LEN = 32;
    private static final int AEAD_TAG_BITS = 128;
    private static final String HKDF_INFO_TAG = "secret-service/hardened/v1";

    private final CollectionInterface wrapped;
    private final KeyMaterialProvider provider;
    private final boolean acknowledgeSecurityTheater;
    private final boolean allowMigration;
    private final HybridKem kem;
    private final EpochKeystore keystore;
    private final GenerationAnchor generationAnchor;

    private volatile String epochId;

    private HardenedCollection(Builder b) {
        this.wrapped = Objects.requireNonNull(b.wrapped, "wrapped collection");
        this.provider = Objects.requireNonNull(b.provider, "key material provider");
        this.acknowledgeSecurityTheater = b.acknowledgeSecurityTheater;
        this.allowMigration = b.allowMigration;
        this.kem = new HybridKem(b.enablePostQuantum);
        this.generationAnchor = b.generationAnchor;
        this.keystore = new EpochKeystore(this.wrapped, this.provider, this.generationAnchor);

        ThreatCoverage tc = provider.threatCoverage();
        if (tc.isSecurityTheaterVsSameUid() && !acknowledgeSecurityTheater) {
            throw new SecurityTheaterException(
                "KeyMaterialProvider " + provider.getClass().getSimpleName()
                        + " declares same-UID threat coverage=NONE: " + tc.rationale()
                        + " If this is a CI/dev build, call .acknowledgeSecurityTheater(true) on the builder."
            );
        }
        this.epochId = b.epochId != null ? b.epochId : newEpochId();

        // Operator-visible posture line: one INFO record per HardenedCollection instance
        // names the provider, the threat coverage it claims, whether the security-theater
        // gate was bypassed, and the time-binding mode. Skim logs to verify your deployment
        // is in the posture you intended.
        log.info(
            "HardenedCollection initialised: provider={}, threatCoverage=[sameUid={}, crossUid={}, offline={}, networkHndl={}], "
                + "acknowledgedTheater={}, totpMode={}, epoch={}",
            provider.getClass().getSimpleName(),
            tc.sameUid(), tc.crossUid(), tc.offline(), tc.networkHndl(),
            acknowledgeSecurityTheater, provider.mode(), epochId);
        if (acknowledgeSecurityTheater) {
            log.warn(
                "HardenedCollection: acknowledgeSecurityTheater=true is set. The configured provider "
                    + "({}) does NOT defend against same-UID attackers. This flag should not appear "
                    + "in production builds.",
                provider.getClass().getSimpleName());
        }
    }

    public static Builder builder(CollectionInterface wrapped, KeyMaterialProvider keyMaterial) {
        return new Builder(wrapped, keyMaterial);
    }

    public static final class Builder {
        private final CollectionInterface wrapped;
        private final KeyMaterialProvider provider;
        private boolean acknowledgeSecurityTheater = false;
        private boolean enablePostQuantum = false;
        private boolean allowMigration = false;
        private String epochId;
        private GenerationAnchor generationAnchor;

        Builder(CollectionInterface wrapped, KeyMaterialProvider provider) {
            this.wrapped = Objects.requireNonNull(wrapped, "wrapped collection");
            this.provider = Objects.requireNonNull(provider, "key material provider");
        }

        public Builder acknowledgeSecurityTheater(boolean b) { this.acknowledgeSecurityTheater = b; return this; }

        /**
         * Enables hybrid X25519 + ML-KEM-768 wrapping. The KEM shared secret participates in the
         * HKDF info string for the per-item DEK; the KEM ciphertext is stored alongside the AEAD
         * ciphertext in the envelope. Per-collection epoch keypairs are persisted as a separate
         * encrypted item in the wrapped collection (the "epoch keystore"). On {@link #rotateEpoch},
         * the old epoch's private key is destroyed, yielding real forward secrecy for ciphertexts
         * written under the previous epoch -- a class-D / HNDL defense.
         *
         * <p>When {@code true}, requires {@code javax.crypto.KEM.getInstance("ML-KEM"|"ML-KEM-768")}
         * to be available -- either JDK 24+ stock, or BouncyCastle 1.82+ on JDK 21-23. Falls back
         * to X25519-only if PQ is unavailable; the kem_id byte then reflects what was actually
         * used so old envelopes remain readable.</p>
         */
        public Builder enablePostQuantum(boolean b) { this.enablePostQuantum = b; return this; }

        /**
         * Allow {@link HardenedCollection#migrateNonHardenedToHardened} to run on this
         * instance. <b>Dual-gated</b>: even with this flag, the env var
         * {@code SECRET_SERVICE_HARDENED_ALLOW_MIGRATION=1} must also be set at runtime.
         * Both are required because migration overwrites items that this layer did not
         * write, which is otherwise refused by the non-destructive design. The two-gate
         * scheme means accidental adoption requires both code-review (the builder call)
         * and an explicit operator action (the env var) before mutating shared state.
         */
        public Builder allowMigration(boolean b) { this.allowMigration = b; return this; }

        /**
         * Anchor the epoch-keystore generation counter in rollback-resistant storage (a TPM NV
         * monotonic counter -- see {@code Tpm2GenerationAnchor} in the {@code hardened-tpm2}
         * module). Without an anchor, an attacker with write access to the keyring store can delete
         * the current keystore item and re-introduce an older, genuine one to resurrect epoch keys
         * that {@link #rotateEpoch} destroyed; with one, a below-floor keystore is refused
         * (fail-closed) on load. Enable this when the collection is <b>created</b> -- see
         * {@link GenerationAnchor} for why retrofitting onto an existing keystore is refused. The
         * anchor is closed when this collection is {@link #close() closed}.
         */
        public Builder generationAnchor(GenerationAnchor anchor) { this.generationAnchor = anchor; return this; }

        // Test/internal-only: lets tests pin a deterministic epoch id. NOT public because
        // operator code that hard-codes an epoch id silently disables forward secrecy
        // (rotateEpoch generates a new id; if the operator keeps overriding it, the keystore
        // never rotates) and a typo in a config file ("yourapp-prod " vs "yourapp-prod")
        // partitions items into unreadable parallel epochs. Production code should let the
        // constructor pick a UUID.
        Builder epochId(String id) { this.epochId = id; return this; }

        public HardenedCollection build() { return new HardenedCollection(this); }
    }

    // ---------- public API ----------

    @Override
    public Optional<String> createItem(String label, CharSequence secret) {
        return createItem(label, secret, new HashMap<>());
    }

    @Override
    public Optional<String> createItem(String label, CharSequence secret, Map<String, String> attributes) {
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(secret, "secret");
        Objects.requireNonNull(attributes, "attributes");

        if (attributes.keySet().stream().anyMatch(k -> k != null && k.startsWith("hardened."))) {
            throw new IllegalArgumentException("attributes under 'hardened.*' are reserved");
        }

        char[] pepper = provider.getPepper();
        // Capture the TOTP step exactly once: the same value must feed DEK derivation and the
        // stored hardened.totp.step attribute, or a step rollover between two currentStep()
        // calls would make the item permanently undecryptable in STORED_STEP mode.
        long totpStep = provider.mode() == KeyMaterialProvider.Mode.NO_TOTP ? 0L : provider.currentStep();
        byte[] totpCode = totpCodeForWrite(totpStep);
        byte[] salt = new byte[Envelope.SALT_LEN];
        new SecureRandom().nextBytes(salt);
        byte[] epochBytes = epochId.getBytes(StandardCharsets.US_ASCII);
        String itemId = UUID.randomUUID().toString();

        byte[] plaintext = charsToUtf8(secret);
        byte[] dek = null;
        byte[] kemSecret = null;
        byte[] nonce = new byte[Envelope.NONCE_LEN];
        KemId kemId = kem.kemId();
        String envelopeB64;
        // Everything that touches key material runs inside this try so a KEM/keystore/AEAD
        // failure both zeroes the sensitive buffers (finally) and returns a fail-safe empty
        // (catch) -- createItem is typed Optional<String>, so it must not leak an exception.
        try {
            // Encapsulate against the current epoch keypair (always on: classical X25519, plus the
            // ML-KEM half when PQ is enabled). The kemSecret is mixed into HKDF; kemCiphertext is
            // stored in the envelope.
            HybridKem.Encapsulation encap = encapsulateForWrite();
            byte[] kemCt = encap.kemCiphertext();
            kemSecret = encap.sharedSecret();
            dek = deriveDek(pepper, totpCode, salt, epochBytes,
                    itemId.getBytes(StandardCharsets.US_ASCII), kemSecret);
            new SecureRandom().nextBytes(nonce);
            byte[] aeadCt;
            try {
                aeadCt = aeadEncrypt(dek, nonce, plaintext, associatedData(salt, epochBytes, itemId));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("AES-GCM encryption failed", e);
            }

            byte flags = 0;
            if (kemId.carriesPqCiphertext()) flags |= Envelope.FLAG_PQ_HYBRID;
            if (provider.mode() == KeyMaterialProvider.Mode.STORED_STEP) flags |= Envelope.FLAG_STORED_STEP_TOTP;
            if (provider.mode() == KeyMaterialProvider.Mode.LIVE_CODE)   flags |= Envelope.FLAG_LIVE_TOTP;

            Envelope env = new Envelope(Envelope.VERSION_1, flags, kemId.id(), salt, epochBytes,
                    kemCt, nonce, aeadCt);
            envelopeB64 = Base64.getEncoder().encodeToString(env.toBytes());
        } catch (IllegalStateException e) {
            // KEM failure (e.g. an epoch keypair could not be loaded/persisted) or AES-GCM
            // failure: report as an empty Optional, never a thrown exception.
            log.warn("createItem: could not seal item '{}': {}", label, e.toString());
            return Optional.empty();
        } finally {
            Arrays.fill(plaintext, (byte) 0);
            if (dek != null) Arrays.fill(dek, (byte) 0);
            Arrays.fill(pepper, '\0');
            Arrays.fill(totpCode, (byte) 0);
            if (kemSecret != null) Arrays.fill(kemSecret, (byte) 0);
        }

        Map<String, String> merged = new LinkedHashMap<>(attributes);
        merged.put(ATTR_VERSION, ATTR_VERSION_V1);
        merged.put(ATTR_EPOCH, epochId);
        merged.put(ATTR_TOTP_MODE, provider.mode().name());
        if (provider.mode() == KeyMaterialProvider.Mode.STORED_STEP) {
            merged.put(ATTR_TOTP_STEP, Long.toString(totpStep));
        }
        merged.put(ATTR_KDF, KDF_ALG);
        merged.put(ATTR_AEAD, AEAD_ALG);
        merged.put(ATTR_KEM, kemId.label());
        merged.put(ATTR_KEM_ID, String.format("0x%02x", kemId.id() & 0xff));
        merged.put("hardened.item.id", itemId);

        return wrapped.createItem(label, envelopeB64, merged);
    }

    @Override
    public Optional<Boolean> matchesSecret(String objectPath, char[] candidate) {
        Objects.requireNonNull(objectPath, "objectPath");
        Objects.requireNonNull(candidate, "candidate");
        try {
            return withSecret(objectPath, plain -> constantTimeEquals(plain, candidate));
        } finally {
            Arrays.fill(candidate, '\0');
        }
    }

    /**
     * Constant-time char[] equality. Runtime depends only on the shorter of the two
     * lengths; every index up to that bound is examined. A length mismatch short-circuits
     * to {@code false} but does not leak the correct length (a remote attacker can
     * usually infer length via other means, and constant-time length-independence would
     * require a fixed iteration bound).
     */
    static boolean constantTimeEquals(char[] a, char[] b) {
        if (a == null || b == null) return false;
        int diff = a.length ^ b.length;
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    @Override
    public <R> Optional<R> withSecret(String objectPath, Function<char[], R> callback) {
        Objects.requireNonNull(objectPath, "objectPath");
        Objects.requireNonNull(callback, "callback");

        Optional<Map<String, String>> attrs = wrapped.getAttributes(objectPath);
        if (attrs.isEmpty() || !ATTR_VERSION_V1.equals(attrs.get().get(ATTR_VERSION))) {
            log.warn("withSecret: {} not a hardened v1 item; refusing to expose plaintext.", objectPath);
            return Optional.empty();
        }

        return wrapped.withSecret(objectPath, envelopeChars -> {
            byte[] envelopeBytes;
            try {
                envelopeBytes = Base64.getDecoder().decode(new String(envelopeChars));
            } catch (IllegalArgumentException e) {
                log.warn("withSecret: envelope rejected for {}", objectPath);
                log.debug("withSecret: envelope for {} is not valid base64", objectPath);
                return null;
            }
            if (!Envelope.looksLikeEnvelope(envelopeBytes)) {
                Arrays.fill(envelopeBytes, (byte) 0);
                log.warn("withSecret: envelope rejected for {}", objectPath);
                log.debug("withSecret: envelope for {} is missing SSv1 magic", objectPath);
                return null;
            }
            Envelope env;
            try {
                env = Envelope.fromBytes(envelopeBytes);
            } catch (RuntimeException e) {
                Arrays.fill(envelopeBytes, (byte) 0);
                log.warn("withSecret: envelope rejected for {}", objectPath);
                log.debug("withSecret: envelope parse failed for {}: {}", objectPath, e.getMessage());
                return null;
            } finally {
                Arrays.fill(envelopeBytes, (byte) 0);
            }

            char[] plain = decryptToChars(env, objectPath, attrs.get());
            if (plain == null) return null;
            try {
                return callback.apply(plain);
            } finally {
                Arrays.fill(plain, '\0');
            }
        });
    }

    @Override
    public <R> Optional<R> withSecrets(Function<Map<String, char[]>, R> callback) {
        Objects.requireNonNull(callback, "callback");
        // Scope strictly to hardened items; foreign items are invisible to this API
        // (matches the non-destructive read policy of withSecret).
        Optional<List<String>> paths = wrapped.getItems(Map.of(ATTR_VERSION, ATTR_VERSION_V1));
        if (paths.isEmpty()) return Optional.empty();
        Map<String, char[]> decoded = new LinkedHashMap<>();
        try {
            for (String path : paths.get()) {
                // Skip the EpochKeystore item -- it carries hardened.version=1 too but is
                // managed by EpochKeystore and is not a user-facing secret.
                Optional<Map<String, String>> a = wrapped.getAttributes(path);
                if (a.isPresent()
                        && EpochKeystore.KIND_VALUE.equals(a.get().get(EpochKeystore.ATTR_KIND))) {
                    continue;
                }
                Optional<Boolean> ok = withSecret(path,
                        secret -> { decoded.put(path, secret.clone()); return Boolean.TRUE; });
                if (ok.isEmpty()) {
                    // Fail-fast: never hand the callback a silently-truncated map.
                    log.warn("withSecrets: {} could not be decrypted; aborting batch.", path);
                    return Optional.empty();
                }
            }
            R result = callback.apply(java.util.Collections.unmodifiableMap(decoded));
            return Optional.ofNullable(result);
        } finally {
            for (char[] v : decoded.values()) Arrays.fill(v, '\0');
        }
    }

    @Override
    public boolean deleteItem(String objectPath) {
        Optional<Map<String, String>> attrs = wrapped.getAttributes(objectPath);
        if (attrs.isEmpty() || !ATTR_VERSION_V1.equals(attrs.get().get(ATTR_VERSION))) {
            log.warn("deleteItem refused: {} is not a hardened item; cross-layer deletes are disallowed.", objectPath);
            return false;
        }
        return wrapped.deleteItem(objectPath);
    }

    @Override
    public boolean rotateEpoch() {
        String previous = this.epochId;
        String next = newEpochId();
        log.info("rotateEpoch: {} -> {} (rewrap pending items)", previous, next);
        // Rewrap every hardened item under the new epoch. Filter out the keystore item itself
        // so rotation doesn't recursively try to rewrap its own keystore (which is encrypted
        // under the pepper, not under the per-epoch KEM).
        Optional<List<String>> paths = wrapped.getItems(Map.of(ATTR_VERSION, ATTR_VERSION_V1));
        if (paths.isEmpty()) {
            this.epochId = next;
            return true;
        }
        this.epochId = next;
        boolean allOk = true;
        for (String path : paths.get()) {
            // Skip the keystore item -- it lives under hardened.kind=epoch-keystore and is
            // managed by EpochKeystore directly, not by the per-item DEK derivation.
            Optional<Map<String, String>> attrs = wrapped.getAttributes(path);
            if (attrs.isPresent()
                    && EpochKeystore.KIND_VALUE.equals(attrs.get().get(EpochKeystore.ATTR_KIND))) {
                continue;
            }
            Boolean ok;
            try {
                ok = wrapped.withSecret(path, envelopeChars -> {
                Optional<Map<String, String>> a = wrapped.getAttributes(path);
                if (a.isEmpty()) return Boolean.FALSE;
                byte[] envBytes;
                try {
                    envBytes = Base64.getDecoder().decode(new String(envelopeChars));
                } catch (IllegalArgumentException e) {
                    return Boolean.FALSE;
                }
                Envelope env = Envelope.fromBytes(envBytes);
                Arrays.fill(envBytes, (byte) 0);
                char[] plain = decryptToChars(env, path, a.get());
                if (plain == null) return Boolean.FALSE;
                try {
                    String label = wrapped.getItemLabel(path).orElse("item");
                    Map<String, String> oldAttrs = new HashMap<>(a.get());
                    // strip hardened.* attributes before merging user-defined ones
                    oldAttrs.keySet().removeIf(k -> k != null && k.startsWith("hardened."));
                    // Create-then-delete: the old envelope survives until the new one
                    // is durably written, so a crash between the two never loses data.
                    Optional<String> created = createItem(label, CharBuffer.wrap(plain), oldAttrs);
                    if (created.isEmpty()) {
                        log.warn("rotateEpoch: rewrap of {} failed; keeping old envelope intact.", path);
                        return Boolean.FALSE;
                    }
                    boolean deleted = wrapped.deleteItem(path);
                    if (!deleted) {
                        log.warn("rotateEpoch: rewrote {} as {} but could not delete the old item; "
                                + "duplicate present until resolved manually.", path, created.get());
                    }
                    return Boolean.TRUE;
                } finally {
                    Arrays.fill(plain, '\0');
                }
                }).orElse(Boolean.FALSE);
            } catch (RuntimeException e) {
                // A rewrap can throw if writing the new envelope fails partway -- e.g. the epoch
                // keystore could not persist the new epoch keypair. The old envelope has not been
                // deleted, so no data is lost; treat this item as a failed rewrap and keep the
                // previous epoch alive.
                log.warn("rotateEpoch: rewrap of {} failed: {}; keeping old envelope intact.",
                        path, e.toString());
                ok = Boolean.FALSE;
            }
            allOk &= ok;
        }
        if (allOk) {
            // Forward secrecy: keep only the new epoch's keypair and destroy every superseded
            // one -- not just `previous`, but any epoch left over from earlier sessions. A fully
            // successful rewrap proves no surviving hardened item references an older epoch (an
            // unreadable item would have failed the rewrap and set allOk=false, keeping all keys),
            // so retaining only `next` can never strand an item. Items captured pre-rotation can
            // no longer be decapsulated by any retained key.
            try {
                keystore.retainOnly(next);
                log.info("rotateEpoch: retained only epoch {}; destroyed all superseded epoch keys "
                        + "(forward secrecy)", next);
            } catch (RuntimeException e) {
                log.warn("rotateEpoch: failed to destroy superseded epoch keys: {}", e.toString());
                allOk = false;
            }
        } else {
            log.warn("rotateEpoch: at least one rewrap failed; keeping previous epoch {} alive "
                    + "in the keystore so straggler items remain readable.", previous);
        }
        return allOk;
    }

    /** Env-var name that, in addition to {@link Builder#allowMigration(boolean)}, must be set to "1" for migration to run. */
    public static final String ENV_ALLOW_MIGRATION = "SECRET_SERVICE_HARDENED_ALLOW_MIGRATION";

    /**
     * One-shot migration: read each non-hardened item in the wrapped collection that
     * matches {@code selector}, write it as a hardened envelope under this collection's
     * configuration, then delete the plain original. Returns a structured report.
     *
     * <h3>Dual-gate</h3>
     * <p>This method is the only one in the library that mutates items the layer didn't
     * write. It is dual-gated: <b>both</b> {@link Builder#allowMigration(boolean)} and the
     * environment variable {@code SECRET_SERVICE_HARDENED_ALLOW_MIGRATION=1} must be set.
     * One requires a code change (visible in PR review); the other requires an explicit
     * operator action at deploy time. Either alone is insufficient.</p>
     *
     * <h3>Failure handling</h3>
     * <p>Per-item failures are recorded in the report and do <b>not</b> abort the batch.
     * On any failure for a given item: the plain original is left intact (we delete only
     * after a successful hardened write), and a {@code Failure} entry is added. Operators
     * can re-run after fixing the failures.</p>
     */
    public MigrationReport migrateNonHardenedToHardened(java.util.function.Predicate<MigrationCandidate> selector) {
        Objects.requireNonNull(selector, "selector");
        if (!allowMigration) {
            throw new SecurityTheaterException(
                "migrateNonHardenedToHardened requires Builder.allowMigration(true). "
                        + "Migration overwrites pre-existing items the hardened layer did not write; "
                        + "the dual-gate (builder + " + ENV_ALLOW_MIGRATION + " env var) prevents accidental adoption.");
        }
        if (!"1".equals(java.lang.System.getenv(ENV_ALLOW_MIGRATION))) {
            throw new SecurityTheaterException(
                "migrateNonHardenedToHardened requires the environment variable "
                        + ENV_ALLOW_MIGRATION + "=1 in addition to Builder.allowMigration(true). "
                        + "This second gate forces an explicit operator action at deploy time, "
                        + "separate from the code change that flipped the builder flag.");
        }
        return migrateInternal(selector);
    }

    /**
     * Test-only hook that runs the migration body, bypassing the env-var gate (we cannot
     * mutate process env from a JUnit test portably). Still requires {@link Builder#allowMigration(boolean)}
     * so the builder-side gate is still pinned by tests.
     */
    MigrationReport migrateNonHardenedToHardenedForTest(java.util.function.Predicate<MigrationCandidate> selector) {
        Objects.requireNonNull(selector, "selector");
        if (!allowMigration) {
            throw new SecurityTheaterException("test hook still requires Builder.allowMigration(true)");
        }
        return migrateInternal(selector);
    }

    private MigrationReport migrateInternal(java.util.function.Predicate<MigrationCandidate> selector) {
        List<MigrationResult> results = new ArrayList<>();
        Optional<List<String>> allPaths = wrapped.getItems(Map.of());
        if (allPaths.isEmpty()) {
            return new MigrationReport(0, 0, 0, results);
        }

        int considered = 0, migrated = 0, skipped = 0, failed = 0;
        for (String path : allPaths.get()) {
            considered++;
            Optional<Map<String, String>> attrs = wrapped.getAttributes(path);
            if (attrs.isEmpty()) { skipped++; continue; }
            Map<String, String> a = attrs.get();
            // Skip items already managed by the hardened layer (or its keystore).
            if (ATTR_VERSION_V1.equals(a.get(ATTR_VERSION))) { skipped++; continue; }
            if (EpochKeystore.KIND_VALUE.equals(a.get(EpochKeystore.ATTR_KIND))) { skipped++; continue; }

            String label = wrapped.getItemLabel(path).orElse("item");
            MigrationCandidate candidate = new MigrationCandidate(path, label, Map.copyOf(a));
            if (!selector.test(candidate)) { skipped++; continue; }

            // Read plain into a char[] we can zero -- never a String, which is immutable and
            // cannot be cleared, so the plaintext would linger on the heap until GC.
            Optional<char[]> plainChars = wrapped.withSecret(path, char[]::clone);
            if (plainChars.isEmpty()) {
                results.add(new MigrationResult(path, false, "could not read plain item"));
                failed++;
                continue;
            }
            char[] plain = plainChars.get();
            // Strip any reserved hardened.* attrs the source unexpectedly carried
            Map<String, String> userAttrs = new LinkedHashMap<>(a);
            userAttrs.keySet().removeIf(k -> k != null && k.startsWith("hardened."));
            // Write hardened
            Optional<String> created;
            try {
                created = createItem(label, CharBuffer.wrap(plain), userAttrs);
            } catch (RuntimeException e) {
                results.add(new MigrationResult(path, false, "createItem threw: " + e.getMessage()));
                failed++;
                continue;
            } finally {
                Arrays.fill(plain, '\0');
            }
            if (created.isEmpty()) {
                results.add(new MigrationResult(path, false, "createItem returned empty"));
                failed++;
                continue;
            }
            // Delete plain only after the hardened copy is durable
            boolean deleted = wrapped.deleteItem(path);
            if (!deleted) {
                results.add(new MigrationResult(path, true,
                        "WARNING: hardened copy at " + created.get() + " written but plain original could not be deleted"));
                migrated++;
                continue;
            }
            results.add(new MigrationResult(path, true, "migrated to " + created.get()));
            migrated++;
        }
        log.info("migrateNonHardenedToHardened: considered={} migrated={} skipped={} failed={}",
                considered, migrated, skipped, failed);
        return new MigrationReport(migrated, skipped, failed, results);
    }

    /** Item the migration helper offers to a selector predicate. */
    public record MigrationCandidate(String path, String label, Map<String, String> attributes) {}

    /** One row of {@link MigrationReport#results()}. */
    public record MigrationResult(String path, boolean success, String detail) {}

    /** Aggregate of one {@link #migrateNonHardenedToHardened} run. */
    public record MigrationReport(int migrated, int skipped, int failed, List<MigrationResult> results) {
        public MigrationReport {
            results = List.copyOf(results);
        }
    }

    @Override
    public HardenedStatus status() {
        return new HardenedStatus(
                epochId,
                java.time.Instant.now(),
                kem.postQuantumAvailable(),
                false,
                provider.mode(),
                provider.threatCoverage(),
                kem.algorithmLabel(),
                AEAD_ALG,
                KDF_ALG
        );
    }

    /**
     * Class name of the {@link KeyMaterialProvider} backing this collection. Useful for
     * diagnostics ({@link HardenedHealthCheck}) and logging without exposing the provider
     * itself, which may hold sensitive material.
     */
    public String providerClassName() {
        return provider.getClass().getName();
    }

    @Override
    public void close() {
        // Close in reverse construction order: provider first (zeroes the pepper cache and
        // releases TPM handles), then the generation anchor (its own TPM handle), then the
        // wrapped CollectionInterface. We swallow each failure independently so a broken
        // component can't strand the others.
        try {
            provider.close();
        } catch (RuntimeException e) {
            log.warn("provider.close() threw: {}", e.toString());
        }
        if (generationAnchor != null) {
            try {
                generationAnchor.close();
            } catch (Exception e) {
                log.warn("generationAnchor.close() threw: {}", e.toString());
            }
        }
        try {
            wrapped.close();
        } catch (Exception e) {
            log.warn("wrapped.close() threw: {}", e.toString());
        }
    }

    // ---------- internals ----------

    private char[] decryptToChars(Envelope env, String objectPath, Map<String, String> attrs) {
        String itemId = attrs.get("hardened.item.id");
        if (itemId == null) {
            log.warn("decrypt: {} missing hardened.item.id attribute", objectPath);
            return null;
        }
        char[] pepper = provider.getPepper();
        // One or more candidate TOTP codes depending on the stored mode: exactly one for
        // NO_TOTP / STORED_STEP, but three for LIVE_CODE (current step and +/-1) so a read
        // that lands one step after the write still succeeds -- the +/-1 tolerance the mode
        // advertises. Each candidate is tried until one decrypts.
        List<byte[]> totpCandidates = totpCodesForRead(attrs);
        byte[] kemSecret;
        try {
            // When the envelope advertises kem_id != NONE, look up the matching epoch keypair
            // and decapsulate env.kemCiphertext() into the shared secret feeding the DEK.
            kemSecret = decapsulateForRead(env);
        } catch (IllegalStateException e) {
            // The envelope's epoch is no longer in the keystore (rotated and destroyed) -- a
            // legitimate read failure, not a programmer error. Return empty (not an exception).
            log.warn("decrypt: cannot read {} -- {}", objectPath, e.getMessage());
            Arrays.fill(pepper, '\0');
            for (byte[] c : totpCandidates) Arrays.fill(c, (byte) 0);
            return null;
        }
        try {
            byte[] idBytes = itemId.getBytes(StandardCharsets.US_ASCII);
            byte[] ad = associatedData(env.salt(), env.epochId(), itemId);
            for (byte[] totpCode : totpCandidates) {
                byte[] dek = null;
                byte[] plain = null;
                try {
                    dek = deriveDek(pepper, totpCode, env.salt(), env.epochId(), idBytes, kemSecret);
                    plain = aeadDecrypt(dek, env.nonce(), env.aeadCiphertext(), ad);
                    return utf8ToChars(plain);
                } catch (GeneralSecurityException e) {
                    // Wrong candidate (or a genuine AEAD failure): try the next candidate.
                } finally {
                    if (dek != null) Arrays.fill(dek, (byte) 0);
                    if (plain != null) Arrays.fill(plain, (byte) 0);
                }
            }
            log.warn("decrypt: AEAD failure for {} (tried {} TOTP candidate(s))",
                    objectPath, totpCandidates.size());
            return null;
        } finally {
            Arrays.fill(pepper, '\0');
            Arrays.fill(kemSecret, (byte) 0);
            for (byte[] c : totpCandidates) Arrays.fill(c, (byte) 0);
        }
    }

    private byte[] totpCodeForWrite(long step) {
        KeyMaterialProvider.Mode m = provider.mode();
        if (m == KeyMaterialProvider.Mode.NO_TOTP) return new byte[0];
        byte[] seed = provider.getTotpSeed().orElse(null);
        if (seed == null) return new byte[0];
        try {
            return Totp.code(seed, step);
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    /**
     * Candidate TOTP codes to try on read, most-likely first. NO_TOTP and unparsable modes
     * yield a single empty code. STORED_STEP yields the one code for the exact stored step.
     * LIVE_CODE yields three codes -- the current step and +/-1 -- so a read that happens just
     * after a step rollover still matches the code used at write time. The list contents are
     * zeroed by the caller.
     */
    private List<byte[]> totpCodesForRead(Map<String, String> attrs) {
        String modeStr = attrs.get(ATTR_TOTP_MODE);
        if (modeStr == null) return List.of(new byte[0]);
        KeyMaterialProvider.Mode storedMode;
        try {
            storedMode = KeyMaterialProvider.Mode.valueOf(modeStr);
        } catch (IllegalArgumentException e) {
            return List.of(new byte[0]);
        }
        if (storedMode == KeyMaterialProvider.Mode.NO_TOTP) return List.of(new byte[0]);
        byte[] seed = provider.getTotpSeed().orElse(null);
        if (seed == null) return List.of(new byte[0]);
        try {
            if (storedMode == KeyMaterialProvider.Mode.STORED_STEP) {
                String s = attrs.get(ATTR_TOTP_STEP);
                if (s == null) return List.of(new byte[0]);
                long step;
                try { step = Long.parseLong(s); } catch (NumberFormatException e) { return List.of(new byte[0]); }
                return List.of(Totp.code(seed, step));
            }
            // LIVE_CODE: tolerate a +/-1 step drift between write and read.
            long step = provider.currentStep();
            return List.of(Totp.code(seed, step), Totp.code(seed, step - 1), Totp.code(seed, step + 1));
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    /**
     * Encapsulate against the current epoch's public keypair. The KEM is always on: with PQ
     * disabled this is a classical X25519 encapsulation ({@code kem_id=KEM_ID_X25519}); with PQ
     * enabled it adds the ML-KEM-768 half ({@code kem_id=KEM_ID_X25519_MLKEM768}). Either way a
     * non-empty {@code kem_ct} is produced and the epoch keystore is consulted, so epoch
     * rotation gives forward secrecy even without a PQ component. The returned shared-secret
     * bytes are zeroed by the caller.
     */
    private HybridKem.Encapsulation encapsulateForWrite() {
        EpochKeystore.EpochKeyPair epochKeys = keystore.getOrCreate(epochId, kem);
        java.security.PublicKey xPub = epochKeys.x25519.getPublic();
        if (xPub == null) {
            // Defensive: keystore-loaded entries may not have a public key for X25519 (we
            // store only the private and re-derive on demand). createItem on a fresh epoch
            // does store the public, so this branch is hit only for pre-loaded epochs that
            // don't carry it. Recover by fetching the keystore-cached encoded public... or
            // just regenerate a fresh keypair (which forfeits forward secrecy across reads
            // of items written under that epoch). Simpler invariant: ensure getOrCreate
            // always returns a usable public key. If we got here, throw -- it's a bug.
            throw new IllegalStateException(
                "Epoch " + epochId + " is missing its X25519 public key; rotate epoch to recover.");
        }
        java.security.PublicKey pqPub = null;
        if (epochKeys.mlkem != null) {
            pqPub = epochKeys.mlkem.getPublic();
        }
        return kem.encapsulate(xPub, pqPub);
    }

    /**
     * Decapsulate the envelope's KEM ciphertext using the matching epoch private keys.
     * Returns the shared secret bytes, or an empty array for envelopes with
     * {@code kem_id=KEM_ID_NONE}. The caller is responsible for zeroing the result.
     */
    private byte[] decapsulateForRead(Envelope env) {
        if (env.kemId() == Envelope.KEM_ID_NONE) return new byte[0];
        String envEpoch = new String(env.epochId(), java.nio.charset.StandardCharsets.US_ASCII);
        java.util.Optional<EpochKeystore.EpochKeyPair> kp = keystore.get(envEpoch);
        if (kp.isEmpty()) {
            throw new IllegalStateException(
                    "Epoch " + envEpoch + " not found in keystore -- key was destroyed (rotated) "
                            + "or keystore missing/corrupt; cannot decrypt envelope.");
        }
        EpochKeystore.EpochKeyPair pair = kp.get();
        if (pair.x25519.getPrivate() == null) {
            throw new IllegalStateException("Epoch " + envEpoch + " is missing its X25519 private key");
        }
        java.security.PrivateKey pqPriv = pair.mlkem == null ? null : pair.mlkem.getPrivate();
        // Only kems that carry a PQ ciphertext half decapsulate as hybrid; a classical X25519
        // envelope must use envelopeIsHybrid=false or the PQ-part check would reject it. Derive
        // this from the KemId table so it can never disagree with the write-side flag.
        boolean envIsHybrid = KemId.fromId(env.kemId()).map(KemId::carriesPqCiphertext).orElse(false);
        return kem.decapsulate(pair.x25519.getPrivate(), pqPriv, env.kemCiphertext(), envIsHybrid);
    }

    /**
     * Derives the per-item DEK. {@code kemSecret} is the optional KEM-derived shared secret;
     * pass an empty array (or {@code null}) for items without a KEM. The HKDF info string
     * domain-separates with-KEM and without-KEM derivations: an envelope written without a
     * KEM cannot be decrypted as if it had one and vice versa.
     */
    private static byte[] deriveDek(char[] pepper, byte[] totpCode, byte[] salt, byte[] epoch,
                                    byte[] itemId, byte[] kemSecret) {
        byte[] pepperBytes = charsToUtf8(CharBuffer.wrap(pepper));
        byte[] kem = kemSecret == null ? new byte[0] : kemSecret;
        try {
            byte[] prk = HKDF.fromHmacSha256().extract(salt, pepperBytes);
            byte[] info = buildInfo(totpCode, epoch, itemId, kem);
            byte[] dek = HKDF.fromHmacSha256().expand(prk, info, AEAD_KEY_LEN);
            Arrays.fill(prk, (byte) 0);
            Arrays.fill(info, (byte) 0);
            return dek;
        } finally {
            Arrays.fill(pepperBytes, (byte) 0);
        }
    }

    private static byte[] buildInfo(byte[] totpCode, byte[] epoch, byte[] itemId, byte[] kemSecret) {
        byte[] tag = HKDF_INFO_TAG.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(
                tag.length + 2 + totpCode.length + 2 + epoch.length + 2 + itemId.length + 2 + kemSecret.length);
        buf.put(tag);
        buf.putShort((short) totpCode.length).put(totpCode);
        buf.putShort((short) epoch.length).put(epoch);
        buf.putShort((short) itemId.length).put(itemId);
        // length-prefix the KEM secret separately so an empty KEM secret yields a deterministic,
        // non-clashing info string vs a present-but-empty one. The two-byte length prefix keeps
        // the info domain-separated even when the secret is absent.
        buf.putShort((short) kemSecret.length).put(kemSecret);
        return buf.array();
    }

    private static byte[] associatedData(byte[] salt, byte[] epoch, String itemId) {
        byte[] id = itemId.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer buf = ByteBuffer.allocate(2 + salt.length + 2 + epoch.length + 2 + id.length);
        buf.putShort((short) salt.length).put(salt);
        buf.putShort((short) epoch.length).put(epoch);
        buf.putShort((short) id.length).put(id);
        return buf.array();
    }

    private static byte[] aeadEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AEAD_TAG_BITS, nonce));
        c.updateAAD(aad);
        return c.doFinal(plaintext);
    }

    private static byte[] aeadDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AEAD_TAG_BITS, nonce));
        c.updateAAD(aad);
        return c.doFinal(ciphertext);
    }

    private static byte[] charsToUtf8(CharSequence cs) {
        CharsetEncoder enc = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        CharBuffer cb = CharBuffer.wrap(cs);
        ByteBuffer out = ByteBuffer.allocate(Math.max(16, cs.length() * 4));
        ByteBuffer tmp = ByteBuffer.allocate(out.capacity());
        CoderResult r = enc.encode(cb, tmp, true);
        if (r.isError()) throw new IllegalArgumentException("secret is not valid UTF-16");
        tmp.flip();
        byte[] bytes = new byte[tmp.remaining()];
        tmp.get(bytes);
        // best-effort zero of the intermediate buffer
        Arrays.fill(tmp.array(), (byte) 0);
        Arrays.fill(out.array(), (byte) 0);
        return bytes;
    }

    private static char[] utf8ToChars(byte[] bytes) {
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        CharBuffer cb = CharBuffer.allocate(bytes.length);
        try {
            CoderResult r = dec.decode(bb, cb, true);
            if (r.isError()) throw new IllegalArgumentException("plaintext is not valid UTF-8");
        } catch (RuntimeException e) {
            Arrays.fill(cb.array(), '\0');
            throw e;
        }
        cb.flip();
        char[] out = new char[cb.remaining()];
        cb.get(out);
        Arrays.fill(cb.array(), '\0');
        return out;
    }

    private static String newEpochId() { return UUID.randomUUID().toString(); }
}
