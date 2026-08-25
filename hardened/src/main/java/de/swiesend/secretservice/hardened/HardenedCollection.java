package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.Hkdf;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * <p>On write, the plaintext is encrypted with an AEAD (AES-256-GCM or ChaCha20-Poly1305) under a
 * per-item DEK derived via HKDF-SHA256 from {pepper, KEM shared secret, per-item salt, epoch id,
 * item id}. The
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
 *       epoch keypair. This gives forward secrecy: an envelope captured <em>before</em> the key was
 *       destroyed can no longer be decapsulated even by an attacker who later learns the pepper.
 *       The guarantee is bounded by two things outside this layer's control: (1) the wrapped store
 *       must actually erase a deleted keystore item (gnome-keyring may retain deleted items in
 *       unallocated space), and (2) <b>backup retention must be rotated too</b> -- an older keyring
 *       backup still containing the pre-rotation keystore, plus the pepper, recovers the old keys,
 *       so without backup discipline the guarantee is only theoretical. A rollback of the keystore
 *       (reintroducing a destroyed epoch) is prevented only when a {@link GenerationAnchor} is
 *       configured (see {@link Builder#generationAnchor}).</li>
 * </ul>
 *
 * <h3>Thread-safety</h3>
 * <p>Concurrent {@link #createItem}, {@link #withSecret}, {@link #withSecrets}, and
 * {@link #matchesSecret} calls on a single instance are safe <em>as long as the wrapped
 * {@link CollectionInterface} is thread-safe</em>: the epoch keystore's mutating methods are
 * {@code synchronized} (so concurrent first-writes create exactly one epoch, not a split-brain), the
 * shared {@code SecureRandom} is thread-safe, and each write uses fresh per-item key material. The
 * epoch-mutating operations {@link #rotateEpoch} and {@link #migrateNonHardenedToHardened} must
 * <b>not</b> run concurrently with writers on the same instance -- quiesce writes around them.</p>
 */
public final class HardenedCollection implements HardenedCollectionInterface {

    private static final Logger log = LoggerFactory.getLogger(HardenedCollection.class);

    /** Shared CSPRNG for salts and nonces; SecureRandom is thread-safe. */
    private static final SecureRandom RANDOM = new SecureRandom();

    static final String ATTR_VERSION    = "hardened.version";
    static final String ATTR_EPOCH      = "hardened.epoch";
    static final String ATTR_KDF        = "hardened.kdf";
    static final String ATTR_AEAD       = "hardened.aead";
    static final String ATTR_KEM        = "hardened.kem";
    static final String ATTR_KEM_ID     = "hardened.kem.id";
    static final String ATTR_VERSION_V1 = "1";

    private static final String KDF_ALG   = "hkdf-sha256";
    private static final int AEAD_KEY_LEN = Aead.KEY_LEN;
    private static final String HKDF_INFO_TAG = "secret-service/hardened/v3";
    /** Reported by {@link #status()} before the first write resolves the collection's epoch. */
    static final String EPOCH_UNRESOLVED = "(unresolved)";
    /** Sentinel from the rotation verification for an item that is not a hardened envelope. */
    private static final String NOT_OURS = "\u0000not-a-hardened-envelope";

    /**
     * Anchors currently backing a live collection, keyed by {@link GenerationAnchor#scopeKey()}.
     *
     * <p>Two collections sharing one anchor brick each other: the floor is global but each keeps its
     * own generation seeded from it, so whichever persists last pushes the other below the floor,
     * which is then refused as a rollback and fails closed on reads and writes. Refusing at
     * construction turns a silent, permanent runtime failure into an immediate, obvious one.</p>
     */
    private static final Map<Object, AnchorClaim> ANCHORS_IN_USE =
            new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * One anchor's claim: which collection holds it, and how many live instances wrap that
     * collection.
     *
     * <p>The count is what makes {@code close()} safe when an application builds two decorators over
     * one collection -- successive configurations of the same keyring, which is legitimate. Without
     * it, closing the first frees the anchor while the second is still writing under it, and a third
     * decorator over a <em>different</em> collection is then admitted: the precise mutual-bricking
     * this registry exists to refuse.</p>
     *
     * <p>{@code liveInstances} is mutated only inside {@code ANCHORS_IN_USE.compute(...)}, so the
     * map's per-bin lock serialises it and no further synchronisation is needed.</p>
     *
     * <p>The holder is a weak reference so that a never-closed decorator does not pin its wrapped
     * collection, and hence its D-Bus session, in static state for the JVM lifetime. Note this is a
     * best-effort fallback, not the release path: applications normally keep their own strong
     * reference to the wrapped collection, so this clears only once the application has dropped it
     * too. {@code close()} is what actually releases an anchor promptly.</p>
     */
    private static final class AnchorClaim {
        private final java.lang.ref.WeakReference<CollectionInterface> holder;
        private int liveInstances;

        AnchorClaim(CollectionInterface holder) {
            this.holder = new java.lang.ref.WeakReference<>(holder);
            this.liveInstances = 1;
        }
    }

    private final CollectionInterface wrapped;
    private final KeyMaterialProvider provider;
    private final boolean acknowledgeSameUidExposure;
    private final boolean allowMigration;
    private final HybridKem kem;
    private final EpochKeystore keystore;
    private final GenerationAnchor generationAnchor;
    private final byte aeadId;
    private final boolean memoryLocked;

    /**
     * Display/reporting cache of the epoch this instance last wrote under. The keystore, not this
     * field, is the source of truth: the current epoch is resolved per write inside the keystore
     * monitor. Null until the first write resolves it.
     */
    private volatile String epochId;
    /** Test-pinned epoch id (package-private builder hook); null in production. */
    private final String pinnedEpochId;
    /** Cleared by {@link #rotateEpoch()} so a rotation is never undone by a stale pin. */
    private volatile boolean pinActive;
    /** Registry key released on close(); null when no anchor is configured. */
    private final Object anchorScopeKey;
    /** Guards close() against running twice; see {@link #close()}. */
    private final java.util.concurrent.atomic.AtomicBoolean closed =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    private final boolean ownsWrapped;
    private final boolean ownsProvider;
    private final boolean ownsAnchor;
    private volatile java.time.Instant epochCreated;

    private HardenedCollection(Builder b) {
        this.wrapped = Objects.requireNonNull(b.wrapped, "wrapped collection");
        this.provider = Objects.requireNonNull(b.provider, "key material provider");
        this.acknowledgeSameUidExposure = b.acknowledgeSameUidExposure;
        this.allowMigration = b.allowMigration;
        this.kem = new HybridKem(b.enablePostQuantum);
        this.generationAnchor = b.generationAnchor;
        this.aeadId = Objects.requireNonNull(b.aead, "aead").id();
        this.memoryLocked = b.lockMemory && MemoryLock.lockAll();
        this.ownsWrapped = b.ownsWrapped;
        this.ownsProvider = b.ownsProvider;
        this.ownsAnchor = b.ownsAnchor;
        this.keystore = new EpochKeystore(this.wrapped, this.provider, this.generationAnchor);

        ThreatCoverage tc = provider.threatCoverage();
        if (tc.hasNoSameUidProtection() && !acknowledgeSameUidExposure) {
            throw new SameUidExposureException(
                "KeyMaterialProvider " + provider.getClass().getSimpleName()
                        + " reports sameUid=NONE: " + tc.rationale()
                        + "\n  What this means: any process running as this OS user can read the key"
                        + " material (an environment variable via /proc/<pid>/environ, a readable"
                        + " file, or this JVM's heap) and decrypt every item. Against that attacker"
                        + " this layer adds nothing."
                        + "\n  What still holds: offline theft of the keyring file, a different UID"
                        + " on this host, and the D-Bus daemon itself all still see only AEAD"
                        + " ciphertext -- encryption is not disabled."
                        + "\n  Production: use a provider that resists same-UID access, e.g."
                        + " Tpm2KeyMaterialProvider, which keeps the pepper sealed in hardware."
                        + "\n  CI/dev: accept the exposure explicitly with"
                        + " .acknowledgeSameUidExposure(true) on the builder."
            );
        }
        // The epoch is a property of the COLLECTION, not of this instance: it is read from (or
        // recorded into) the keystore on the first write, so every instance over a collection
        // converges on one epoch instead of minting a UUID per process and growing the keystore
        // forever. Resolution is deliberately deferred -- the constructor does no D-Bus I/O.
        this.pinnedEpochId = b.epochId;
        this.pinActive = b.epochId != null;
        this.epochId = b.epochId; // null in production until the first write resolves it
        this.epochCreated = java.time.Instant.now();

        // Operator-visible posture line: one INFO record per HardenedCollection instance names the
        // provider, the threat coverage it claims, whether the security-theater gate was bypassed,
        // the AEAD suite, and whether an anti-rollback anchor is present. Skim logs to verify your
        // deployment is in the posture you intended.
        boolean hasAnchor = generationAnchor != null;
        log.info(
            "HardenedCollection initialised: provider={}, threatCoverage=[sameUid={}, crossUid={}, offline={}, networkHndl={}], "
                + "sameUidExposureAccepted={}, aead={}, generationAnchor={}, epoch={}",
            provider.getClass().getSimpleName(),
            tc.sameUid(), tc.crossUid(), tc.offline(), tc.networkHndl(),
            acknowledgeSameUidExposure, Aead.label(aeadId), hasAnchor ? "present" : "none",
            epochId != null ? epochId : EPOCH_UNRESOLVED);
        if (acknowledgeSameUidExposure && !b.suppressSameUidExposureWarning) {
            log.warn(
                "HardenedCollection: same-UID exposure accepted (acknowledgeSameUidExposure=true). "
                    + "Provider {} does not protect secrets from another process running as this "
                    + "user. Items are still AEAD-encrypted at rest, so offline, cross-UID and "
                    + "daemon-level access remain protected -- but this configuration should not "
                    + "ship to production.",
                provider.getClass().getSimpleName());
        }
        // F-1: forward secrecy relies on the epoch keystore's generation being anti-rollback
        // protected. Without a GenerationAnchor, a party that can write the keyring store can
        // resurrect an older keystore snapshot and undo a rotateEpoch() destruction. Warn loudly
        // when post-quantum / HNDL protection is requested but no anchor backs it.
        if (b.enablePostQuantum && !hasAnchor) {
            log.warn(
                "HardenedCollection: enablePostQuantum(true) without a GenerationAnchor. Forward "
                    + "secrecy via rotateEpoch() can be silently undone by a keyring-writer that "
                    + "reintroduces a destroyed epoch. Configure a Tpm2GenerationAnchor for "
                    + "rollback-resistant HNDL protection.");
        }
        // Registered LAST, after every statement that can throw. Registering earlier meant a
        // build() refused by the same-UID gate (or by a provider whose threatCoverage() threw) left
        // a permanent entry behind: a later, correct collection over a DIFFERENT collection was
        // then refused, blaming one that was never constructed.
        this.anchorScopeKey = registerAnchor();
    }

    /**
     * Claims this collection's anchor, or throws if another live collection already holds it.
     *
     * <p>A cleared reference counts as free. Every successful registration -- including the second
     * and later instances over the same collection -- returns the key and must release it on close,
     * so the claim survives until the last of them is closed.</p>
     *
     * @return the key to release on close, or null when there is nothing to release
     */
    private Object registerAnchor() {
        if (generationAnchor == null) return null;
        Object key = generationAnchor.scopeKey();
        ANCHORS_IN_USE.compute(key, (k, cur) -> {
            if (cur != null) {
                CollectionInterface held = cur.holder.get();
                // Several instances over the SAME collection are fine -- that is just successive
                // configurations sharing one keystore and one generation lineage. What bricks both
                // is one anchor backing two DIFFERENT collections.
                if (held == wrapped) {
                    cur.liveInstances++;
                    return cur;
                }
                if (held != null) {
                    throw new IllegalStateException(
                            "GenerationAnchor " + key + " already backs a different live "
                                    + "HardenedCollection. An anchor must back exactly one collection: "
                                    + "the floor is global but each collection keeps its own generation, "
                                    + "so sharing one pushes each collection below the other's floor and "
                                    + "both end up refused as rollbacks (fail-closed on reads and "
                                    + "writes). Provision one NV counter per collection -- or, if these "
                                    + "are two views of the same collection, pass the same "
                                    + "CollectionInterface instance.");
                }
                // held == null: the previous holder was collected, so the claim is stale. Fall
                // through and replace it -- its instance count describes objects that no longer
                // exist and must not keep the anchor reserved.
            }
            return new AnchorClaim(wrapped);
        });
        return key;
    }

    public static Builder builder(CollectionInterface wrapped, KeyMaterialProvider keyMaterial) {
        return new Builder(wrapped, keyMaterial);
    }

    public static final class Builder {
        private final CollectionInterface wrapped;
        private final KeyMaterialProvider provider;
        private boolean acknowledgeSameUidExposure = false;
        private boolean suppressSameUidExposureWarning = false;
        private boolean enablePostQuantum = false;
        private boolean allowMigration = false;
        private String epochId;
        private GenerationAnchor generationAnchor;
        private AeadId aead = AeadId.AES_256_GCM;
        private boolean lockMemory = false;
        // Ownership: you close what you constructed. All three default to false -- close() must not
        // tear down objects the caller handed us (closing `wrapped` also drops the D-Bus session).
        private boolean ownsWrapped = false;
        private boolean ownsProvider = false;
        private boolean ownsAnchor = false;

        Builder(CollectionInterface wrapped, KeyMaterialProvider provider) {
            this.wrapped = Objects.requireNonNull(wrapped, "wrapped collection");
            this.provider = Objects.requireNonNull(provider, "key material provider");
        }

        /**
         * Accepts that the configured {@link KeyMaterialProvider} offers no defence against an
         * attacker running as the <b>same OS user</b>, and that you are deploying it anyway.
         *
         * <p>Required whenever the provider reports {@link ThreatCoverage#hasNoSameUidProtection()}
         * -- {@link de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider} is the
         * built-in example. Without it, {@link #build()} throws {@link SameUidExposureException}.</p>
         *
         * <h4>What you are accepting</h4>
         * <p>The pepper lives somewhere any process with your UID can read: an environment variable
         * (exposed through {@code /proc/<pid>/environ}), a file you can open, or this JVM's heap.
         * Such an attacker recovers the pepper and decrypts every item, so for that attacker class
         * this layer adds nothing.</p>
         *
         * <h4>What still holds</h4>
         * <p>Encryption is <em>not</em> disabled and the other attacker classes are unaffected: an
         * attacker who steals the keyring file offline, a different UID on the same host, and the
         * D-Bus daemon itself all still see only AEAD ciphertext. This flag narrows the claim you
         * are entitled to make; it does not weaken the ciphertext.</p>
         *
         * <h4>When this is legitimate</h4>
         * <p>CI, automated tests and local development -- anywhere the same-UID attacker is out of
         * scope by construction. It should not appear in a production build; a loud warning is
         * logged when it does.</p>
         *
         * <h4>What to use instead</h4>
         * <p>A provider that actually resists same-UID access. {@code Tpm2KeyMaterialProvider}
         * keeps the pepper sealed in hardware and rates same-UID {@code PARTIAL} -- the honest
         * ceiling, since a same-UID attacker can still ask the TPM to unseal exactly as your
         * process does, but cannot walk off with the pepper.</p>
         */
        public Builder acknowledgeSameUidExposure(boolean b) { this.acknowledgeSameUidExposure = b; return this; }

        /**
         * Silences the per-instance WARN that {@link #acknowledgeSameUidExposure(boolean)} otherwise
         * logs on every construction. Off by default; only meaningful once the exposure has been
         * acknowledged.
         *
         * <p>Intended for CI and test suites that build many collections and where the exposure is
         * a deliberate, already-understood property of the environment -- there the warning is pure
         * log noise and drowns out real findings. It changes nothing about the exposure itself.</p>
         *
         * <p>Do not use it to quieten a production deployment: the warning is the only runtime
         * signal that secrets in that process are readable by any same-UID attacker. Silence the
         * cause by switching to a provider that resists same-UID access, not the symptom.</p>
         */
        public Builder suppressSameUidExposureWarning(boolean b) { this.suppressSameUidExposureWarning = b; return this; }

        /**
         * Selects the AEAD cipher for new items (default {@link AeadId#AES_256_GCM}). The choice is
         * recorded in the authenticated {@code aead_id} envelope byte, so items written under either
         * cipher stay readable regardless of the current default.
         */
        public Builder aead(AeadId aead) { this.aead = Objects.requireNonNull(aead, "aead"); return this; }

        /**
         * Attempt to lock all process memory ({@code mlockall}) so pepper/DEK buffers cannot swap to
         * disk. Off by default: it is a whole-process operation that can fail on a low
         * {@code RLIMIT_MEMLOCK}, and silent operation needs
         * {@code --enable-native-access=de.swiesend.secretservice.hardened}. When enabled,
         * {@link HardenedStatus#memoryLocked()} reports whether the lock actually took.
         */
        public Builder lockMemory(boolean b) { this.lockMemory = b; return this; }

        /**
         * Transfers ownership of the wrapped {@link CollectionInterface} to this instance, so
         * {@link HardenedCollection#close()} closes it. <b>Off by default</b>: the collection was
         * constructed by the caller, and closing it also tears down the underlying D-Bus session,
         * which silently breaks any other code sharing that connection.
         */
        public Builder ownsWrapped(boolean b) { this.ownsWrapped = b; return this; }

        /**
         * Transfers ownership of the {@link KeyMaterialProvider} to this instance, so
         * {@link HardenedCollection#close()} closes it (zeroing its cached pepper). <b>Off by
         * default</b>: one provider is commonly shared across several collections, and closing it
         * makes every other holder fail.
         */
        public Builder ownsProvider(boolean b) { this.ownsProvider = b; return this; }

        /**
         * Transfers ownership of the {@link GenerationAnchor} to this instance, so
         * {@link HardenedCollection#close()} closes it (releasing its TPM handle). <b>Off by
         * default.</b>
         */
        public Builder ownsAnchor(boolean b) { this.ownsAnchor = b; return this; }

        /**
         * Enables hybrid X25519 + ML-KEM-768 wrapping. The KEM shared secret participates in the
         * HKDF derivation of the per-item DEK; the KEM ciphertext is stored alongside the AEAD
         * ciphertext in the envelope. Per-collection epoch keypairs are persisted as a separate
         * encrypted item in the wrapped collection (the "epoch keystore"). On {@link #rotateEpoch},
         * the old epoch's private key is destroyed, giving forward secrecy for ciphertexts written
         * under the previous epoch -- a class-D / HNDL defense, <b>bounded by backup-retention
         * discipline and by configuring a {@link #generationAnchor} against keystore rollback</b>
         * (see the class Javadoc's "KEM and forward secrecy" section).
         *
         * <p>When {@code true}, requires {@code javax.crypto.KEM.getInstance("ML-KEM-768")} to be
         * available. On this module's JDK 25 floor it is provided natively by the stock SunJCE
         * provider (JEP 496), so no third-party crypto provider is needed. Falls back to X25519-only
         * if PQ is unavailable; the kem_id byte then reflects what was actually used so old envelopes
         * remain readable.</p>
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
         * anchor is NOT closed by {@link #close()} unless {@link #ownsAnchor(boolean)} is set --
         * close it yourself otherwise, or the TPM handle leaks. An anchor must back exactly ONE
         * collection; constructing a second collection with the same anchor is refused (see
         * {@link GenerationAnchor#scopeKey()}).
         */
        public Builder generationAnchor(GenerationAnchor anchor) { this.generationAnchor = anchor; return this; }

        // Test/internal-only: lets tests pin a deterministic epoch id. NOT public because
        // operator code that hard-codes an epoch id silently disables forward secrecy
        // (epoch rotation generates a new id; if the operator keeps overriding it, the keystore
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

        // Fetched INSIDE the try below: a closed provider throws IllegalStateException, and out
        // here that would escape createItem's Optional<String> contract.
        char[] pepper = null;
        byte[] salt = new byte[Envelope.SALT_LEN];
        RANDOM.nextBytes(salt);
        String itemId = UUID.randomUUID().toString();

        // Encoded INSIDE the try below, for the same reason as the pepper: charsToUtf8 rejects an
        // unpaired surrogate with IllegalArgumentException, and a lone surrogate is easy to produce
        // by splitting a char[] through an emoji. Out here that would escape createItem's
        // Optional<String> contract on nothing more than an odd input.
        byte[] plaintext = null;
        byte[] idBytes = itemId.getBytes(StandardCharsets.US_ASCII);
        byte[] dek = null;
        byte[] kemSecret = null;
        byte[] nonce = new byte[Envelope.NONCE_LEN];
        // Set from the ACTUAL encapsulation below, never from the runtime PQ preference: an epoch
        // minted while PQ was off has no ML-KEM half, so stamping kem_id from kem.kemId() would
        // advertise a hybrid envelope whose kem_ct is classical-only -- unreadable forever.
        KemId kemId;
        String envelopeB64;
        // Everything that touches key material runs inside this try so a KEM/keystore/AEAD
        // failure both zeroes the sensitive buffers (finally) and returns a fail-safe empty
        // (catch) -- createItem is typed Optional<String>, so it must not leak an exception.
        String writeEpoch;
        byte[] epochBytes;
        try {
            plaintext = charsToUtf8(secret);
            pepper = provider.getPepper();
            // ONE epoch snapshot for the whole write. Reading the field separately for the AAD, the
            // KEM lookup and the attribute would let a concurrent epoch rotation produce an envelope
            // whose AAD/DEK name epoch B while kem_ct was encapsulated to epoch A -- permanently
            // undecryptable.
            EpochKeystore.Current cur = resolveEpochForWrite();
            writeEpoch = cur.epochId();
            epochBytes = writeEpoch.getBytes(StandardCharsets.US_ASCII);
            this.epochId = writeEpoch; // reporting cache only
            // Encapsulate against the current epoch keypair (always on: classical X25519, plus the
            // ML-KEM half when PQ is enabled). The kemSecret is mixed into HKDF; kemCiphertext is
            // stored in the envelope.
            HybridKem.Encapsulation encap = encapsulateForWrite(cur.keys(), writeEpoch);
            kemId = encap.postQuantum() ? KemId.X25519_MLKEM768 : KemId.X25519;
            byte[] kemCt = encap.kemCiphertext();
            kemSecret = encap.sharedSecret();
            dek = deriveDek(pepper, salt, epochBytes, idBytes, kemSecret);
            RANDOM.nextBytes(nonce);

            byte flags = 0;
            if (kemId.carriesPqCiphertext()) flags |= Envelope.FLAG_PQ_HYBRID;

            // AAD binds the whole header (version, flags, aead_id, kdf_id, kem_id, salt, epoch,
            // item-id, kem_ct, nonce), so item identity and the cipher suite are authenticated by the
            // AEAD rather than trusted from mutable D-Bus attributes on read.
            byte[] aad = Envelope.associatedData(Envelope.VERSION_3, flags, aeadId,
                    Envelope.KDF_ID_HKDF_SHA256, kemId.id(), salt, epochBytes, idBytes, kemCt, nonce);
            byte[] aeadCt;
            try {
                aeadCt = Aead.encrypt(aeadId, dek, nonce, plaintext, aad);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("AEAD encryption failed", e);
            }

            Envelope env = new Envelope(Envelope.VERSION_3, flags, aeadId, Envelope.KDF_ID_HKDF_SHA256,
                    kemId.id(), salt, epochBytes, idBytes, kemCt, nonce, aeadCt);
            envelopeB64 = Base64.getEncoder().encodeToString(env.toBytes());
        } catch (RuntimeException e) {
            // KEM failure (e.g. an epoch keypair could not be loaded/persisted), AEAD failure, or
            // any other unchecked failure while sealing: report as an empty Optional, never a
            // thrown exception -- createItem is typed Optional<String>. Catching only
            // IllegalStateException here left every other unchecked type free to escape the very
            // contract the comment above asserts.
            log.warn("createItem: could not seal item '{}': {}", label, e.toString());
            return Optional.empty();
        } finally {
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
            if (dek != null) Arrays.fill(dek, (byte) 0);
            if (pepper != null) Arrays.fill(pepper, '\0');
            if (kemSecret != null) Arrays.fill(kemSecret, (byte) 0);
        }

        Map<String, String> merged = new LinkedHashMap<>(attributes);
        merged.put(ATTR_VERSION, ATTR_VERSION_V1);
        merged.put(ATTR_EPOCH, writeEpoch);
        merged.put(ATTR_KDF, KDF_ALG);
        merged.put(ATTR_AEAD, Aead.label(aeadId));
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

            char[] plain = decryptToChars(env, objectPath);
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
        if (generationAnchor == null) {
            // The rotation about to happen destroys the superseded epoch keys -- the forward-secrecy
            // primitive. Without an anti-rollback anchor, a party that can write the keyring store can
            // reintroduce the pre-rotation keystore snapshot and resurrect those keys, silently undoing
            // the guarantee. See GenerationAnchor / Tpm2GenerationAnchor.
            log.warn("rotateEpoch: no GenerationAnchor configured. The forward secrecy this rotation "
                    + "creates can be undone by a keyring-writer that rolls the keystore back to a "
                    + "pre-rotation snapshot -- and because the collection's current epoch is "
                    + "recorded in the keystore, such a rollback also redirects FUTURE writes onto "
                    + "the resurrected epoch, not just past ones. Configure a Tpm2GenerationAnchor "
                    + "to make it rollback-resistant.");
        }
        String previous = keystore.peekCurrent().orElse(this.epochId);
        String next = newEpochId();
        log.info("rotateEpoch: {} -> {} (rewrap pending items)", previous, next);
        // Rewrap every hardened item under the new epoch. Filter out the keystore item itself
        // so rotation doesn't recursively try to rewrap its own keystore (which is encrypted
        // under the pepper, not under the per-epoch KEM).
        Optional<List<String>> paths = wrapped.getItems(Map.of(ATTR_VERSION, ATTR_VERSION_V1));
        if (paths.isEmpty()) {
            // Enumeration FAILED (as opposed to succeeding with nothing found -- the functional
            // Collection now distinguishes the two). We cannot know what would have needed
            // rewrapping, so we neither rotate nor destroy anything, and we report failure. This
            // used to return true after advancing the epoch, claiming a forward secrecy it had not
            // established.
            log.warn("rotateEpoch: could not enumerate items; refusing to rotate. No keys destroyed.");
            return false;
        }
        // Commit the new epoch BEFORE rewrapping anything under it: adoptAsCurrent writes the
        // keypair and records it current in one persist. Rewrapping first would seal items under
        // an epoch whose private key existed only in this JVM's heap.
        try {
            keystore.adoptAsCurrent(next, kem);
        } catch (RuntimeException e) {
            log.warn("rotateEpoch: could not commit the new epoch {}: {}; staying on {}.",
                    next, e.toString(), previous);
            return false;
        }
        // Only now does this instance start writing under `next`. Because the assignment follows
        // the durable commit, a failure above leaves us writing under `previous`, whose keys still
        // exist -- no rollback of this field is needed.
        this.epochId = next;
        this.epochCreated = java.time.Instant.now();
        this.pinActive = false; // a rotation supersedes any test-pinned epoch
        boolean allOk = true;
        int rewrapped = 0;
        for (String path : paths.get()) {
            // Skip the keystore item -- it lives under hardened.kind=epoch-keystore and is
            // managed by EpochKeystore directly, not by the per-item DEK derivation.
            Optional<Map<String, String>> attrs = wrapped.getAttributes(path);
            // Skip the keystore item, and skip anything whose attributes we cannot read at all --
            // rewrapping an item we cannot classify is the riskier of the two options.
            if (attrs.isEmpty()
                    || EpochKeystore.KIND_VALUE.equals(attrs.get().get(EpochKeystore.ATTR_KIND))) {
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
                char[] plain = decryptToChars(env, path);
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
            if (Boolean.TRUE.equals(ok)) rewrapped++;
        }
        if (allOk) {
            // Forward secrecy: keep only the new epoch's keypair and destroy every superseded
            // one -- not just `previous`, but any epoch left over from earlier sessions. A fully
            // successful rewrap proves no surviving hardened item references an older epoch (an
            // unreadable item would have failed the rewrap and set allOk=false, keeping all keys),
            // so retaining only `next` can never strand an item. Items captured pre-rotation can
            // no longer be decapsulated by any retained key.
            //
            // "Fully successful" must also mean "actually examined something": allOk is initialised
            // true outside the loop, so a zero-iteration loop used to reach here having proved
            // nothing. Verify by re-enumerating -- every surviving hardened item must now name the
            // new epoch -- before destroying any key.
            try {
                if (!rewrapCovered(next, rewrapped)) {
                    log.warn("rotateEpoch: could not verify that every item now references epoch {}; "
                            + "keeping all epoch keys. Re-run rotation once the collection is readable.", next);
                    return false;
                }
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
     *
     * @throws MigrationNotPermittedException if either gate is unset; nothing is read, written or
     *         deleted in that case
     * @throws NullPointerException if {@code selector} is null
     */
    public MigrationReport migrateNonHardenedToHardened(java.util.function.Predicate<MigrationCandidate> selector) {
        Objects.requireNonNull(selector, "selector");
        if (!allowMigration) {
            throw new MigrationNotPermittedException(
                "migrateNonHardenedToHardened requires Builder.allowMigration(true). "
                        + "Migration overwrites pre-existing items the hardened layer did not write; "
                        + "the dual-gate (builder + " + ENV_ALLOW_MIGRATION + " env var) prevents accidental adoption.");
        }
        if (!"1".equals(java.lang.System.getenv(ENV_ALLOW_MIGRATION))) {
            throw new MigrationNotPermittedException(
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
            throw new MigrationNotPermittedException("test hook still requires Builder.allowMigration(true)");
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
            // The SELECTOR RUNS FIRST, before anything reads a body. It is the documented mechanism
            // for restricting what migration touches, so probing ahead of it would let migration
            // decrypt items the caller explicitly excluded -- the selector could no longer prevent
            // what it exists to prevent. Everything above this line is attribute-only.
            if (!selector.test(candidate)) { skipped++; continue; }

            // Selected. Only now may we look at the body. The attribute alone is not proof of what
            // this item is: it is plaintext and daemon-mutable. An item whose hardened.version was
            // stripped but whose body is an SSv1 envelope is still ours, and re-wrapping it would
            // double-envelope it (the base64 envelope becoming the new "plaintext"). Check the magic
            // before treating anything as plaintext.
            if (Boolean.TRUE.equals(wrapped.withSecret(path, body -> {
                try {
                    return Envelope.looksLikeEnvelope(Base64.getDecoder().decode(new String(body)));
                } catch (IllegalArgumentException notBase64) {
                    return Boolean.FALSE; // not base64 -> cannot be one of our envelopes
                } catch (RuntimeException e) {
                    return Boolean.FALSE;
                }
            }).orElse(Boolean.FALSE))) { skipped++; continue; }

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
        // HardenedStatus requires a non-null epoch, but the epoch is resolved lazily on the first
        // write and status() must not perform D-Bus I/O. Report the sentinel until then.
        String e = this.epochId;
        return new HardenedStatus(
                e != null ? e : EPOCH_UNRESOLVED,
                epochCreated,
                kem.postQuantumAvailable(),
                memoryLocked,
                provider.threatCoverage(),
                kem.algorithmLabel(),
                Aead.label(aeadId),
                KDF_ALG
        );
    }

    /**
     * Class name of the {@link KeyMaterialProvider} backing this collection. Useful for
     * diagnostics and logging without exposing the provider
     * itself, which may hold sensitive material.
     */
    public String providerClassName() {
        return provider.getClass().getName();
    }

    @Override
    public void close() {
        // Idempotent. try-with-resources plus an explicit close() is ordinary usage, and a second
        // pass must not decrement the anchor claim again -- that would free an anchor another live
        // instance is still writing under, which is exactly what the claim count prevents.
        if (!closed.compareAndSet(false, true)) return;
        // You close what you constructed. All three of these were handed to us by the caller, so by
        // default we close NONE of them -- closing `wrapped` would also tear down the caller's
        // D-Bus session, and closing a shared provider would break every other holder. Callers who
        // want the old behaviour opt in per object via Builder.ownsProvider/ownsAnchor/ownsWrapped.
        // Close in reverse construction order, swallowing each failure independently so a broken
        // component can't strand the others.
        if (ownsProvider) {
            try {
                provider.close();
            } catch (RuntimeException e) {
                log.warn("provider.close() threw: {}", e.toString());
            }
        }
        if (anchorScopeKey != null) {
            // Bookkeeping of ours, not the anchor's lifecycle: released whether or not we own it,
            // so a closed collection frees its anchor for a replacement instance. The claim drops
            // only when the LAST instance over this collection closes -- see AnchorClaim.
            ANCHORS_IN_USE.computeIfPresent(anchorScopeKey, (k, claim) -> {
                CollectionInterface held = claim.holder.get();
                if (held != null && held != wrapped) return claim; // reclaimed by someone else
                return (--claim.liveInstances <= 0) ? null : claim;
            });
        }
        if (ownsAnchor && generationAnchor != null) {
            try {
                generationAnchor.close();
            } catch (Exception e) {
                log.warn("generationAnchor.close() threw: {}", e.toString());
            }
        }
        if (ownsWrapped) {
            try {
                wrapped.close();
            } catch (Exception e) {
                log.warn("wrapped.close() threw: {}", e.toString());
            }
        }
    }

    // ---------- internals ----------

    private char[] decryptToChars(Envelope env, String objectPath) {
        // Item identity and cipher suite come from the AUTHENTICATED envelope, not from mutable
        // D-Bus attributes: they are covered by the AEAD associated data, so tampering fails
        // decryption rather than steering it.
        if (!Aead.isSupported(env.aeadId()) || env.kdfId() != Envelope.KDF_ID_HKDF_SHA256) {
            log.warn("decrypt: {} names an unsupported cipher suite (aead_id=0x{}, kdf_id=0x{}); refusing.",
                    objectPath, Integer.toHexString(env.aeadId() & 0xff), Integer.toHexString(env.kdfId() & 0xff));
            return null;
        }
        // The kem gets the same treatment as the other two selector bytes. Without this an id we
        // cannot execute -- an unknown future id, or the reserved x25519+hqc-192 -- was decapsulated
        // as classical and surfaced as "AEAD authentication failed", i.e. a format/config problem
        // reported as tampering. Envelope's javadoc promises the reader rejects such an id here.
        if (!KemId.fromId(env.kemId()).map(KemId::implemented).orElse(false)) {
            log.warn("decrypt: {} names an unsupported KEM (kem_id=0x{}, {}); refusing.",
                    objectPath, Integer.toHexString(env.kemId() & 0xff), KemId.labelFor(env.kemId()));
            return null;
        }
        byte[] idBytes = env.itemId();
        // Fetched INSIDE the try: a closed provider throws IllegalStateException, and out here that
        // would escape withSecret/withSecrets/matchesSecret, all of which return Optional.
        char[] pepper = null;
        byte[] kemSecret;
        try {
            pepper = provider.getPepper();
            // When the envelope advertises kem_id != NONE, look up the matching epoch keypair
            // and decapsulate env.kemCiphertext() into the shared secret feeding the DEK.
            kemSecret = decapsulateForRead(env);
        } catch (RuntimeException e) {
            // Any failure here is a read failure, not a programmer error, and must not escape:
            // withSecret/withSecrets/matchesSecret are contractually Optional-returning.
            // IllegalStateException = the epoch is gone (rotated and destroyed).
            // IllegalArgumentException = a malformed kem_ct, which Envelope cannot fully validate:
            // it only checks that kem_ct_len does not overrun the buffer, so a single flipped byte
            // at rest (e.g. kem_ct_len = 1) parses fine and then blows up in unpackKemCiphertext.
            // Catching only IllegalStateException let that escape to the caller AND skipped the
            // pepper zeroing below, leaving it in the heap.
            log.warn("decrypt: cannot read {} -- {}", objectPath, e.getMessage());
            if (pepper != null) Arrays.fill(pepper, '\0');
            return null;
        }
        byte[] dek = null;
        byte[] plain = null;
        try {
            byte[] ad = env.associatedData();
            dek = deriveDek(pepper, env.salt(), env.epochId(), idBytes, kemSecret);
            plain = Aead.decrypt(env.aeadId(), dek, env.nonce(), env.aeadCiphertext(), ad);
            return utf8ToChars(plain);
        } catch (GeneralSecurityException e) {
            log.warn("decrypt: AEAD authentication failed for {}", objectPath);
            return null;
        } finally {
            if (dek != null) Arrays.fill(dek, (byte) 0);
            if (plain != null) Arrays.fill(plain, (byte) 0);
            Arrays.fill(pepper, '\0');
            Arrays.fill(kemSecret, (byte) 0);
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
    /**
     * Resolves the epoch this write seals under, inside the keystore monitor.
     *
     * <p>A pinned epoch (test hook) is used verbatim but is never recorded as the collection's
     * current epoch -- otherwise a fixture's id would leak into production instances sharing the
     * collection. Otherwise the collection's recorded current epoch is reused, or minted and
     * recorded atomically on first use.</p>
     */
    private EpochKeystore.Current resolveEpochForWrite() {
        if (pinActive && pinnedEpochId != null) {
            return new EpochKeystore.Current(pinnedEpochId, keystore.getOrCreate(pinnedEpochId, kem));
        }
        return keystore.currentOrCreate(kem, HardenedCollection::newEpochId);
    }

    private HybridKem.Encapsulation encapsulateForWrite(EpochKeystore.EpochKeyPair epochKeys, String epoch) {
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
                "Epoch " + epoch + " is missing its X25519 public key; rotate epoch to recover.");
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
     * Derives the per-item DEK. The secret inputs -- the pepper and the KEM-derived shared secret --
     * are concatenated into the HKDF <em>input keying material</em> and mixed by
     * {@code HKDF-Extract(salt, IKM)}; the public per-item context (a domain tag, the epoch id, and
     * the item id) goes into {@code HKDF-Expand}'s {@code info}. This is the textbook shape: an
     * attacker must know every secret input to reconstruct the DEK, and the length-prefixed IKM keeps
     * an absent KEM input distinct from a present-but-empty one, so a with-KEM and a without-KEM
     * derivation can never collide. {@code kemSecret} may be {@code null}/empty for KEM-less items.
     */
    private static byte[] deriveDek(char[] pepper, byte[] salt, byte[] epoch, byte[] itemId, byte[] kemSecret) {
        byte[] pepperBytes = charsToUtf8(CharBuffer.wrap(pepper));
        byte[] kem = kemSecret == null ? new byte[0] : kemSecret;
        byte[] ikm = buildIkm(pepperBytes, kem);
        try {
            byte[] info = buildInfo(epoch, itemId);
            byte[] dek = Hkdf.extractThenExpandSha256(salt, ikm, info, AEAD_KEY_LEN);
            Arrays.fill(info, (byte) 0);
            return dek;
        } finally {
            Arrays.fill(ikm, (byte) 0);
            Arrays.fill(pepperBytes, (byte) 0);
        }
    }

    /** Length-prefixed concatenation of the secret keying inputs: pepper || kemSecret. */
    private static byte[] buildIkm(byte[] pepper, byte[] kemSecret) {
        ByteBuffer buf = ByteBuffer.allocate(2 + pepper.length + 2 + kemSecret.length);
        buf.putShort((short) pepper.length).put(pepper);
        buf.putShort((short) kemSecret.length).put(kemSecret);
        return buf.array();
    }

    /** Public per-item context for HKDF-Expand: domain tag || epoch || item id (length-prefixed). */
    private static byte[] buildInfo(byte[] epoch, byte[] itemId) {
        byte[] tag = HKDF_INFO_TAG.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(tag.length + 2 + epoch.length + 2 + itemId.length);
        buf.put(tag);
        buf.putShort((short) epoch.length).put(epoch);
        buf.putShort((short) itemId.length).put(itemId);
        return buf.array();
    }

    private static byte[] charsToUtf8(CharSequence cs) {
        CharsetEncoder enc = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        CharBuffer cb = CharBuffer.wrap(cs);
        ByteBuffer tmp = ByteBuffer.allocate(Math.max(16, cs.length() * 4));
        try {
            CoderResult r = enc.encode(cb, tmp, true);
            // Rejecting an unpaired surrogate is deliberate -- a REPLACE policy would silently
            // substitute U+FFFD and seal a secret that no longer round-trips. Callers must treat
            // this as a bad-input failure, not encode-and-hope.
            if (r.isError()) throw new IllegalArgumentException("secret is not valid UTF-16");
            tmp.flip();
            byte[] bytes = new byte[tmp.remaining()];
            tmp.get(bytes);
            return bytes;
        } finally {
            // In the finally, not just on success: on the error path tmp already holds everything
            // encoded up to the bad surrogate, which is most of the plaintext.
            Arrays.fill(tmp.array(), (byte) 0);
        }
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

    /**
     * Positive proof that destroying the superseded epoch keys is safe: re-enumerate the collection
     * and require every surviving hardened item to name {@code newEpoch}. Returns false if the
     * enumeration fails, or if any item still references an older epoch.
     *
     * <p>{@code rewrapped == 0} is allowed only when the re-enumeration confirms there is genuinely
     * nothing left to rewrap -- rotating an empty collection is legitimate; rotating a collection we
     * merely failed to read is not.</p>
     */
    private boolean rewrapCovered(String newEpoch, int rewrapped) {
        // Enumerate EVERYTHING, not the hardened.version filter the rewrap loop uses. Attributes are
        // plaintext and daemon-mutable, and this project already documents SearchItems as unreliable
        // per provider (see the KeePassXC note in core's Collection.getItems). An item missing from
        // a filtered result would be invisible to both the rewrap and this check, and we would
        // destroy the only key that reads it. The empty-map form is served from the Items property.
        Optional<List<String>> after = wrapped.getItems(Map.of());
        if (after.isEmpty()) {
            return false; // enumeration failed: we cannot prove anything
        }
        for (String path : after.get()) {
            Optional<Map<String, String>> attrs = wrapped.getAttributes(path);
            if (attrs.isEmpty()) return false; // cannot read it -> cannot clear it
            if (EpochKeystore.KIND_VALUE.equals(attrs.get().get(EpochKeystore.ATTR_KIND))) continue;
            // Read the body ONLY of items that declare themselves ours. The class contract is that
            // the decorator never reads pre-existing non-hardened items, and reading them here would
            // pull other applications' plaintext into this heap and can raise an interactive prompt
            // per item -- on the shared default collection this decorator is built for, that is a
            // large and surprising blast radius for what is meant to be a key-rotation bookkeeping
            // step.
            //
            // Note the asymmetry, which is what makes trusting the attribute safe HERE: the marker
            // is trusted only to decide whether to LOOK at an item, and a lie in that direction just
            // costs us a read of our own item. WHICH epoch the item is under is still taken from the
            // AEAD-authenticated header below and never from hardened.epoch -- that is the direction
            // where a daemon-planted lie would make us destroy a key that is still in use.
            //
            // The residual gap is an item of ours whose hardened.* attributes a hostile daemon
            // stripped: we skip it, and rotation could destroy its key. That is accepted, because a
            // daemon able to rewrite attributes can delete the item outright -- integrity against the
            // storage backend itself is not a property this layer can offer. The unreliable-search
            // case that motivated enumerating everything is still covered: the empty-map enumeration
            // above is served from the Items property, not SearchItems.
            if (!declaresHardened(attrs.get())) continue;
            Optional<String> envEpoch = wrapped.withSecret(path, body -> {
                byte[] raw;
                try {
                    raw = Base64.getDecoder().decode(new String(body));
                } catch (IllegalArgumentException notBase64) {
                    // POSITIVE PROOF this is not an SSv1 envelope -- every envelope we write is
                    // base64. Ordinary passwords are usually not valid base64 ("hunter2!" throws on
                    // '!'), so mapping this to "could not read" would make rotateEpoch return false
                    // forever on any collection holding one foreign item, silently disabling forward
                    // secrecy on exactly the shared-collection deployment this targets.
                    return NOT_OURS;
                }
                try {
                    // Classify by the SSv1 magic. A body that decodes but lacks the magic references
                    // no epoch key either, so it is equally NOT_OURS.
                    if (!Envelope.looksLikeEnvelope(raw)) return NOT_OURS;
                    // Past the magic: this IS one of ours, so a parse failure is a corrupt envelope
                    // that may still reference an old epoch. That must block the destruction.
                    return new String(Envelope.fromBytes(raw).epochId(), StandardCharsets.US_ASCII);
                } catch (RuntimeException corruptEnvelope) {
                    return null;
                } finally {
                    Arrays.fill(raw, (byte) 0);
                }
            });
            if (envEpoch.isEmpty() || envEpoch.get() == null) {
                log.warn("rotateEpoch: could not read the body of {}; not destroying keys.", path);
                return false;
            }
            if (NOT_OURS.equals(envEpoch.get())) continue;   // wears our marker but is not an envelope
            if (!newEpoch.equals(envEpoch.get())) {
                log.warn("rotateEpoch: item {} is still sealed under epoch {}; not destroying keys.",
                        path, envEpoch.get());
                return false;
            }
        }
        if (rewrapped == 0) {
            log.info("rotateEpoch: no items needed rewrapping; the collection holds no hardened items.");
        }
        return true;
    }

    /**
     * Whether an item's attributes mark it as written by this decorator. Used only to decide whether
     * reading an item's body is permitted -- never to decide which epoch it is sealed under, which is
     * always taken from the AEAD-authenticated envelope header.
     */
    private static boolean declaresHardened(Map<String, String> attrs) {
        return attrs.keySet().stream().anyMatch(k -> k != null && k.startsWith("hardened."));
    }

    private static String newEpochId() { return UUID.randomUUID().toString(); }
}
