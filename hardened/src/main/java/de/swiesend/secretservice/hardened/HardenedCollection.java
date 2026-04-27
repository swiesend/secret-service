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
 * <h3>Intentional limitations in v1</h3>
 * <ul>
 *   <li>DEK derivation uses the pepper directly; no per-collection KEM keypair is persisted.
 *       {@link HybridKem} is scaffolded for a future version that adds X25519+ML-KEM forward
 *       secrecy via epoch-ratcheting of a real keypair.</li>
 *   <li>{@code rotateEpoch} generates a fresh epoch id and rewraps items under the new id.
 *       This gives salt-domain separation but not cryptographic forward secrecy — the old
 *       pepper still decrypts the old ciphertext if it was snapshotted.</li>
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
    private final HybridKem kem;
    private final EpochKeystore keystore;

    private volatile String epochId;

    private HardenedCollection(Builder b) {
        this.wrapped = Objects.requireNonNull(b.wrapped, "wrapped collection");
        this.provider = Objects.requireNonNull(b.provider, "key material provider");
        this.acknowledgeSecurityTheater = b.acknowledgeSecurityTheater;
        this.kem = new HybridKem(b.enablePostQuantum);
        this.keystore = new EpochKeystore(this.wrapped, this.provider);

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
        private String epochId;

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
        public Builder epochId(String id) { this.epochId = id; return this; }

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
        byte[] totpCode = totpCodeForWrite();
        byte[] salt = new byte[Envelope.SALT_LEN];
        new SecureRandom().nextBytes(salt);
        byte[] epochBytes = epochId.getBytes(StandardCharsets.US_ASCII);
        String itemId = UUID.randomUUID().toString();

        byte[] plaintext = charsToUtf8(secret);
        byte[] dek = null;
        byte[] nonce = new byte[Envelope.NONCE_LEN];
        byte[] aeadCt;
        // Encapsulate against the current epoch's public key when PQ is enabled. encapsulateForWrite
        // returns a (kemCiphertext, kemSecret) pair, both empty when PQ is disabled. The kemSecret
        // is mixed into HKDF below; kemCiphertext is stored alongside the AEAD ciphertext.
        HybridKem.Encapsulation encap = encapsulateForWrite();
        byte[] kemCt = encap == null ? new byte[0] : encap.kemCiphertext();
        byte[] kemSecret = encap == null ? new byte[0] : encap.sharedSecret();
        String envelopeB64;
        try {
            dek = deriveDek(pepper, totpCode, salt, epochBytes,
                    itemId.getBytes(StandardCharsets.US_ASCII), kemSecret);
            new SecureRandom().nextBytes(nonce);
            try {
                aeadCt = aeadEncrypt(dek, nonce, plaintext, associatedData(salt, epochBytes, itemId));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("AES-GCM encryption failed", e);
            }

            byte kemId = kem.kemId();
            byte flags = 0;
            if (kemId != Envelope.KEM_ID_NONE) flags |= Envelope.FLAG_PQ_HYBRID;
            if (provider.mode() == KeyMaterialProvider.Mode.STORED_STEP) flags |= Envelope.FLAG_STORED_STEP_TOTP;
            if (provider.mode() == KeyMaterialProvider.Mode.LIVE_CODE)   flags |= Envelope.FLAG_LIVE_TOTP;

            Envelope env = new Envelope(Envelope.VERSION_1, flags, kemId, salt, epochBytes,
                    kemCt == null ? new byte[0] : kemCt, nonce, aeadCt);
            envelopeB64 = Base64.getEncoder().encodeToString(env.toBytes());
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
            merged.put(ATTR_TOTP_STEP, Long.toString(provider.currentStep()));
        }
        merged.put(ATTR_KDF, KDF_ALG);
        merged.put(ATTR_AEAD, AEAD_ALG);
        merged.put(ATTR_KEM, kem.algorithmLabel());
        merged.put(ATTR_KEM_ID, String.format("0x%02x", kem.kemId() & 0xff));
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
            Boolean ok = wrapped.withSecret(path, envelopeChars -> {
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
            allOk &= ok;
        }
        if (allOk) {
            // Forward secrecy: drop the old epoch's private keys from the keystore. Items
            // captured pre-rotation can no longer be decapsulated. Only run on full success
            // so we never strand items behind a destroyed key.
            try {
                keystore.removeEpoch(previous);
                log.info("rotateEpoch: destroyed previous epoch {} keypair (forward secrecy)", previous);
            } catch (RuntimeException e) {
                log.warn("rotateEpoch: failed to destroy previous epoch {}: {}", previous, e.toString());
                allOk = false;
            }
        } else {
            log.warn("rotateEpoch: at least one rewrap failed; keeping previous epoch {} alive "
                    + "in the keystore so straggler items remain readable.", previous);
        }
        return allOk;
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

    @Override
    public void close() {
        try {
            wrapped.close();
        } catch (Exception e) {
            log.warn("wrapped.close() threw: {}", e.toString());
        }
    }

    // ---------- internals ----------

    private char[] decryptToChars(Envelope env, String objectPath, Map<String, String> attrs) {
        char[] pepper = provider.getPepper();
        byte[] totpCode = totpCodeForRead(attrs);
        byte[] dek = null;
        byte[] plain = null;
        try {
            String itemId = attrs.get("hardened.item.id");
            if (itemId == null) {
                log.warn("decrypt: {} missing hardened.item.id attribute", objectPath);
                return null;
            }
            // Step E hook: when the envelope advertises kem_id != NONE, look up the matching
            // epoch keypair, decapsulate env.kemCiphertext(), and pass the resulting shared
            // secret. For now keystore wiring is staged in Step C; classical envelopes work.
            byte[] kemSecret = decapsulateForRead(env);
            try {
                dek = deriveDek(pepper, totpCode, env.salt(), env.epochId(),
                        itemId.getBytes(StandardCharsets.US_ASCII), kemSecret);
                plain = aeadDecrypt(dek, env.nonce(), env.aeadCiphertext(),
                        associatedData(env.salt(), env.epochId(), itemId));
                return utf8ToChars(plain);
            } finally {
                Arrays.fill(kemSecret, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            log.warn("decrypt: AEAD failure for {}: {}", objectPath, e.getMessage());
            return null;
        } catch (IllegalStateException e) {
            // Raised by decapsulateForRead when the envelope's epoch is no longer in the
            // keystore (rotated and destroyed) -- a legitimate read failure, not a programmer
            // error. Surface as a warn log + empty so withSecret returns Optional.empty().
            log.warn("decrypt: cannot read {} -- {}", objectPath, e.getMessage());
            return null;
        } finally {
            Arrays.fill(pepper, '\0');
            Arrays.fill(totpCode, (byte) 0);
            if (dek != null) Arrays.fill(dek, (byte) 0);
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    private byte[] totpCodeForWrite() {
        KeyMaterialProvider.Mode m = provider.mode();
        if (m == KeyMaterialProvider.Mode.NO_TOTP) return new byte[0];
        byte[] seed = provider.getTotpSeed().orElse(null);
        if (seed == null) return new byte[0];
        try {
            return Totp.code(seed, provider.currentStep());
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    private byte[] totpCodeForRead(Map<String, String> attrs) {
        String modeStr = attrs.get(ATTR_TOTP_MODE);
        if (modeStr == null) return new byte[0];
        KeyMaterialProvider.Mode storedMode;
        try {
            storedMode = KeyMaterialProvider.Mode.valueOf(modeStr);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
        if (storedMode == KeyMaterialProvider.Mode.NO_TOTP) return new byte[0];
        byte[] seed = provider.getTotpSeed().orElse(null);
        if (seed == null) return new byte[0];
        try {
            long step;
            if (storedMode == KeyMaterialProvider.Mode.STORED_STEP) {
                String s = attrs.get(ATTR_TOTP_STEP);
                if (s == null) return new byte[0];
                try { step = Long.parseLong(s); } catch (NumberFormatException e) { return new byte[0]; }
            } else {
                step = provider.currentStep();
            }
            return Totp.code(seed, step);
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    /**
     * Encapsulate against the current epoch's public keypair. Returns {@code null} when PQ
     * is disabled (writes go through with {@code kem_id=KEM_ID_NONE} and an empty kem_ct).
     * The returned shared-secret bytes are zeroed by the caller.
     */
    private HybridKem.Encapsulation encapsulateForWrite() {
        if (kem.kemId() == Envelope.KEM_ID_NONE) return null;
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
        boolean envIsHybrid = env.kemId() != Envelope.KEM_ID_NONE;
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
