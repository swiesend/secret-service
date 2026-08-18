package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.Hkdf;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
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
import java.util.Set;

/**
 * Per-collection store of {@code epoch_id → (X25519 keypair, ML-KEM keypair)} pairs.
 * Persisted as a single hardened item inside the wrapped {@code CollectionInterface},
 * encrypted under a deterministic AES-256-GCM key derived from the pepper.
 *
 * <h3>Why a separate item</h3>
 * pepper alone (then it would not survive an epoch rotation destroying it),
 * and we don't want yet another out-of-band file.
 * destroying it), and we don't want yet another out-of-band file. Storing the
 * keystore as a hardened-but-special item in the same collection means the same
 * backup that captures the user's secrets also captures the epoch keys -- which
 * is the realistic operational story (lose the keyring file → lose access).
 * The keystore is encrypted; the ciphertext-at-rest is opaque to the daemon,
 * the same as any other hardened item.</p>
 *
 * <h3>Forward secrecy via destruction</h3>
 * <p>{@link #retainOnly(String)} drops every (epochId → keypairs) entry but one and
 * re-persists the keystore. Once a rotation
 * has rewrapped all items under the new epoch and removed the old epoch's entry,
 * old envelopes (e.g. captured from a backup taken pre-rotation) cannot be
 * decapsulated even by an attacker who later compromises the host -- the private
 * key is gone. This is the class-D / HNDL defense the {@code kem_id} byte
 * advertises.</p>
 *
 * <h3>Wire format (inside the AES-256-GCM ciphertext)</h3>
 * <pre>
 * version(1)=0x03 | generation(8) | current_len(1) | current_epoch_id[current_len] | n_entries(2) |
 *   ( id_len(1) | id[id_len] | x25519_priv_len(2) | x25519_priv[..] | x25519_pub_len(2) | x25519_pub[..] |
 *     mlkem_priv_len(2) | mlkem_priv[..] | mlkem_pub_len(2) | mlkem_pub[..] ) repeated
 * </pre>
 *
 * <p>{@code generation} increments on every persist. Persisting is create-then-delete, so
 * a crash can leave two decryptable keystore items; on load the highest generation wins
 * and provably-superseded duplicates are deleted. Picking by generation (not item order)
 * matters: loading a stale keystore would either resurrect epoch keys that
 * {@link #retainOnly} destroyed (breaking forward secrecy) or drop keys created
 * after the stale snapshot (stranding items).</p>
 *
 * <p>The X25519 public key is stored (version 2+) so a loaded epoch can be encapsulated
 * against, not just decapsulated -- every write consults the keystore now that the KEM is
 * always on. Version 1 keystores (no stored X25519 public) still load; their epochs are
 * read-only and upgrade to version 2 on the next persist. ML-KEM public keys are kept so
 * re-wraps don't recompute. Private parts are PKCS#8-encoded; public parts are X.509 SPKI.</p>
 *
 * <h3>On-bus envelope</h3>
 * <p>The keystore item lives at label {@link #LABEL} with attribute
 * {@code hardened.kind = epoch-keystore}. The body is base64 of
 * {@code nonce(12) || aead_ct} -- a vanilla AES-256-GCM envelope, no further
 * structure (no kem_id, no salt, no item_uuid: the keystore IS the keystore for
 * everything else).</p>
 */
final class EpochKeystore {

    private static final Logger log = LoggerFactory.getLogger(EpochKeystore.class);

    static final String LABEL = "__hardened_epoch_keystore__";
    static final String ATTR_KIND = "hardened.kind";
    static final String KIND_VALUE = "epoch-keystore";

    // VERSION_1: version|generation(8)|n|( id | x25519_priv | mlkem_priv | mlkem_pub )*  (read-only).
    // VERSION_2 adds x25519_pub after x25519_priv so a loaded epoch can be encapsulated against
    // (writes need the epoch public key). V1 entries load with a null X25519 public -- readable,
    // but not writable under -- which is fine because V1 epochs are only ever read.
    // VERSION_3 inserts the collection's current epoch id after `generation`:
    //   version|generation(8)|current_len(1)|current|n|( entry )*
    // It lives inside the AES-GCM ciphertext rather than in a D-Bus attribute because attributes
    // are plaintext and daemon-mutable, and because the id and the keys it names must be updated in
    // ONE authenticated write -- a second write would reopen the "minted but not recorded" window.
    // current_len == 0 means "no current epoch recorded" (a V1/V2 blob read after upgrade).
    private static final byte VERSION_1 = 0x01;
    private static final byte VERSION_2 = 0x02;
    private static final byte VERSION_3 = 0x03;
    private static final int NONCE_LEN = 12;
    private static final int KEK_LEN = 32; // AES-256
    private static final int TAG_BITS = 128;
    private static final byte[] KEK_INFO = "secret-service/hardened/epoch-keystore-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEK_FIXED_SALT = "epoch-keystore-salt-v1".getBytes(StandardCharsets.UTF_8);

    /**
     * Seam for the ML-KEM import, so a test can simulate a JVM without an ML-KEM provider.
     *
     * <p>{@code PqProviderBootstrap.ensurePqProvider()} probes the real runtime, so there is no
     * honest way to make ML-KEM genuinely absent in-process; without this seam the data-loss path
     * that motivated retaining the raw bytes cannot be exercised at all.</p>
     */
    @FunctionalInterface
    interface MlKemImporter { KeyPair importKeyPair(byte[] pkcs8Priv, byte[] x509Pub); }

    private static volatile MlKemImporter mlKemImporter = HybridKem::importMlKemKeyPair;

    /** Test hook: swap the ML-KEM importer; pass null to restore the real one. */
    static void setMlKemImporterForTesting(MlKemImporter importer) {
        mlKemImporter = importer != null ? importer : HybridKem::importMlKemKeyPair;
    }

    static final class EpochKeyPair {
        final KeyPair x25519;
        final KeyPair mlkem;            // null when PQ is not used, OR when import failed
        final byte[] mlkemPubEncoded;   // cached so we don't re-encode on every encap
        /**
         * The ML-KEM private exactly as it was read from (or will be written to) the blob.
         *
         * <p>Kept so a keypair we could not <em>import</em> is not therefore <em>destroyed</em>.
         * {@link #serialize} used to re-encode the private from the {@link KeyPair}, so when
         * {@code mlkem} was null -- which happens whenever this JVM has no ML-KEM provider -- it
         * wrote a zero-length private and the next persist made the loss permanent, even after
         * returning to a PQ-capable JVM. With the bytes retained, a round-trip through a PQ-less
         * JVM changes nothing on disk. Null only when this epoch genuinely has no PQ half.</p>
         */
        final byte[] mlkemPrivEncoded;

        EpochKeyPair(KeyPair x25519, KeyPair mlkem, byte[] mlkemPubEncoded, byte[] mlkemPrivEncoded) {
            this.x25519 = x25519;
            this.mlkem = mlkem;
            this.mlkemPubEncoded = mlkemPubEncoded == null ? null : mlkemPubEncoded.clone();
            this.mlkemPrivEncoded = mlkemPrivEncoded == null ? null : mlkemPrivEncoded.clone();
        }

        /** True when this epoch has a PQ half on disk, whether or not we could import it. */
        boolean hasStoredPqHalf() {
            return mlkemPrivEncoded != null && mlkemPubEncoded != null;
        }
    }

    private final CollectionInterface wrapped;
    private final KeyMaterialProvider provider;
    /** Optional anti-rollback anchor (TPM NV counter); null when not configured. */
    private final GenerationAnchor anchor;
    /** Mutable in-memory map; persisted on every change via {@link #persist}. */
    private final Map<String, EpochKeyPair> entries = new LinkedHashMap<>();
    /** Path of the persisted keystore item, set after first persist or load. */
    private String keystorePath;
    /** Monotonic persist counter; the highest generation wins when duplicates exist. */
    private long generation = 0L;
    /**
     * The collection's current epoch -- the one new writes seal under. Recorded in the blob so
     * every instance over this collection converges on ONE epoch instead of minting a fresh UUID
     * per process and growing the keystore without bound. Null until resolved, or when a V1/V2
     * blob (which has no such field) was loaded.
     */
    private String currentEpochId;
    /**
     * Set when a load was refused because the snapshot sat below the anti-rollback floor. Sticky
     * for the instance's lifetime: without it the refusal left {@code keystorePath == null}, so the
     * next persist created a SECOND keystore item at {@code floor + 1} and deleted nothing --
     * whereupon the following load picked that (empty) item as the highest generation and destroyed
     * the genuine snapshot. A refusal must never become the destruction it was meant to prevent.
     */
    private boolean refused = false;

    EpochKeystore(CollectionInterface wrapped, KeyMaterialProvider provider) {
        this(wrapped, provider, null);
    }

    EpochKeystore(CollectionInterface wrapped, KeyMaterialProvider provider, GenerationAnchor anchor) {
        this.wrapped = Objects.requireNonNull(wrapped, "wrapped");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.anchor = anchor;
    }

    /**
     * Read the keystore from the wrapped collection, decrypt, populate the in-memory map.
     * Idempotent; safe to call before reads / writes that touch the keystore.
     */
    synchronized void loadIfPresent() {
        if (keystorePath != null) return; // already loaded
        // Enumerate EVERYTHING and filter by attribute locally -- never locate the keystore with a
        // filtered SearchItems query. This project documents SearchItems as unreliable per provider
        // (see the KeePassXC note in core's Collection.getItems), and HardenedCollection's
        // rewrapCovered refuses to trust it for the same reason: a filtered search that comes back
        // SUCCESSFULLY EMPTY while the keystore item exists would land on "genuinely no keystore
        // yet", and the next persist forks a second keystore at generation 1 -- the exact
        // catastrophe the failed-search guard below exists to prevent, one branch over. The
        // empty-map form is served from the Items property, not SearchItems.
        Optional<List<String>> allPaths = wrapped.getItems(Map.of());
        if (allPaths.isEmpty()) {
            // The ENUMERATION FAILED -- which is not the same as "this collection has no keystore".
            // Treating it as absent is catastrophic: the next write mints a fresh epoch and
            // persists it with previousPath == null, so the genuine keystore is not replaced but
            // JOINED by a second one at generation 1. The following load picks the real one (higher
            // generation) and deletes ours as superseded, taking with it the only copy of the keys
            // for everything written in this session. Fail closed instead. Deliberately NOT sticky
            // (unlike the rollback-floor refusal): a failed enumeration is a transient daemon
            // condition, and the throw alone already prevents the fork -- nothing gets to write.
            // The caller may simply retry once the daemon answers again.
            throw new IllegalStateException(
                    "EpochKeystore: could not enumerate the collection's items (the enumeration "
                            + "failed, which is not the same as finding none). Refusing to read or "
                            + "write rather than risk forking a second keystore and losing epoch "
                            + "keys. Retry once the provider answers again.");
        }
        List<String> candidates = new ArrayList<>();
        for (String path : allPaths.get()) {
            Optional<Map<String, String>> attrs = wrapped.getAttributes(path);
            if (attrs.isEmpty()) {
                // Cannot classify this item -- it MIGHT be the keystore. Proceeding as if it were
                // not risks the same second-keystore fork as a failed enumeration. Fail closed.
                throw new IllegalStateException(
                        "EpochKeystore: could not read the attributes of " + path + " while "
                                + "locating the keystore; it might be the keystore itself. Refusing "
                                + "to read or write rather than risk forking a second keystore.");
            }
            if (KIND_VALUE.equals(attrs.get().get(ATTR_KIND))) candidates.add(path);
        }
        if (candidates.isEmpty()) {
            return; // genuinely no keystore yet -- the first persist will create it
        }
        // An interrupted persist (create-then-delete) can leave two decryptable keystore
        // items; a stale keystore written under a different pepper is also possible. Decrypt
        // every candidate and load the highest generation -- item order proves nothing.
        if (candidates.size() > 1) {
            log.warn("EpochKeystore: found {} keystore items; loading the highest generation.",
                    candidates.size());
        }
        String bestPath = null;
        Parsed best = null;
        List<String> superseded = new ArrayList<>();
        List<String> peers = new ArrayList<>(); // same generation as the winner: another writer's
        for (String path : candidates) {
            Parsed parsed = wrapped.withSecret(path, body -> {
                byte[] raw;
                try {
                    raw = Base64.getDecoder().decode(new String(body));
                } catch (IllegalArgumentException e) {
                    log.warn("EpochKeystore: keystore body at {} is not valid base64", path);
                    return null;
                }
                try {
                    byte[] plain = aeadDecrypt(deriveKek(provider.getPepper()), raw);
                    try {
                        return deserialize(plain);
                    } catch (RuntimeException e) {
                        // Decrypted but did not parse: an unknown/older wire format or a truncated
                        // body. Treat as undecryptable rather than letting the exception escape and
                        // crash the whole load.
                        log.warn("EpochKeystore: keystore at {} decrypted but did not parse: {}",
                                path, e.toString());
                        return null;
                    } finally {
                        Arrays.fill(plain, (byte) 0);
                    }
                } catch (GeneralSecurityException e) {
                    log.warn("EpochKeystore: existing keystore at {} could not be decrypted: {}",
                            path, e.getMessage());
                    return null;
                } finally {
                    Arrays.fill(raw, (byte) 0);
                }
            }).orElse(null);
            if (parsed == null) continue; // undecryptable: not ours to judge, leave it alone
            if (best == null || parsed.generation > best.generation) {
                // Only a STRICTLY lower generation is provably superseded and safe to delete.
                if (bestPath != null) {
                    if (best.generation < parsed.generation) superseded.add(bestPath);
                    else peers.add(bestPath);
                }
                best = parsed;
                bestPath = path;
            } else if (parsed.generation < best.generation) {
                superseded.add(path);
            } else {
                // Equal generation: this is another writer's snapshot at the same generation, not
                // garbage. Deleting it used to destroy that writer's epoch keys outright -- and
                // which of the two "won" was decided by daemon-returned item order, which proves
                // nothing. A collection is single-writer by contract; if we see a peer, say so
                // loudly and leave it alone.
                peers.add(path);
            }
        }
        if (!peers.isEmpty()) {
            log.error("EpochKeystore: found {} keystore item(s) at the same generation ({}). A "
                    + "collection must have a single writer -- concurrent writers will lose epoch "
                    + "keys. Leaving the peer snapshot(s) in place: {}",
                    peers.size(), best != null ? best.generation : -1, peers);
        }
        if (best == null) return;
        if (anchor != null) {
            long floor = anchor.read();
            if (best.generation < floor) {
                // The highest decryptable snapshot is below the anti-rollback floor. Either the
                // keystore was rolled back (an attacker re-introduced an older, genuine snapshot)
                // or the anchor was (re-)provisioned under a pre-existing keystore. Fail closed:
                // do not load, so KEM-wrapped reads return empty rather than silently resurrecting
                // epoch keys that a rotation destroyed.
                log.error("EpochKeystore: keystore generation {} is below the anti-rollback floor {}; "
                        + "refusing to load (possible keystore rollback). KEM-wrapped reads will "
                        + "fail closed and writes will be refused. Operator action required: "
                        + "restore the genuine keystore, or re-provision the anchor if it was "
                        + "reset under an existing keystore.", best.generation, floor);
                this.refused = true;
                return;
            }
            if (best.generation > floor) {
                // A prior persist durably wrote this snapshot but crashed before advancing the
                // anchor (write-ahead ordering). Catch the anchor up so the floor tracks reality.
                log.warn("EpochKeystore: keystore generation {} exceeds the anchor floor {}; catching "
                        + "the anchor up (a prior persist did not complete its advance).",
                        best.generation, floor);
                anchor.advanceTo(best.generation);
            }
        }
        entries.clear();
        entries.putAll(best.entries);
        this.currentEpochId = best.currentEpochId;
        this.generation = best.generation;
        this.keystorePath = bestPath;
        // Provably-superseded duplicates (ours, older generation) are safe to remove now.
        for (String stale : superseded) {
            if (wrapped.deleteItem(stale)) {
                log.info("EpochKeystore: removed superseded duplicate keystore item {}", stale);
            } else {
                log.warn("EpochKeystore: could not remove superseded keystore item {}", stale);
            }
        }
    }

    /** The collection's current epoch together with its keypair, resolved atomically. */
    record Current(String epochId, EpochKeyPair keys) {}

    /**
     * Returns the collection's current epoch, minting and recording one if none exists yet.
     *
     * <p>This is how every instance over a collection converges on a single epoch. The mint and
     * the entry land in the SAME {@link #persist()} inside the same synchronized block, so there is
     * no window where an epoch is in use but not durably recorded.</p>
     */
    synchronized Current currentOrCreate(HybridKem kem, java.util.function.Supplier<String> idFactory) {
        loadIfPresent();
        if (currentEpochId != null) {
            EpochKeyPair held = entries.get(currentEpochId);
            if (held != null) return new Current(currentEpochId, upgradePqIfNeeded(currentEpochId, held, kem));
            // Recorded current with no entry: a corrupt blob, or a bug. Do NOT re-mint keys under
            // the same id -- every existing item naming it would then decapsulate against the wrong
            // key and fail AEAD forever. Mint a fresh id instead and leave the old items' fate to
            // whatever key material still exists.
            log.error("EpochKeystore: recorded current epoch {} has no keypair; minting a new epoch "
                    + "rather than regenerating keys under the same id.", currentEpochId);
        }
        String id = validateEpochId(idFactory.get());
        String previousCurrent = currentEpochId;
        long generationBefore = generation;
        EpochKeyPair fresh = newEpochKeyPair(kem);
        entries.put(id, fresh);
        currentEpochId = id;
        try {
            persist();
        } catch (RuntimeException e) {
            entries.remove(id);
            currentEpochId = previousCurrent;
            generation = generationBefore;
            throw e;
        }
        return new Current(id, fresh);
    }

    /** The recorded current epoch, if any. Loads, but never mints and never persists. */
    synchronized Optional<String> peekCurrent() {
        loadIfPresent();
        return Optional.ofNullable(currentEpochId);
    }

    /**
     * Rotation step one: mint {@code epochId}'s keypair AND record it as current in a single
     * persist, keeping every existing entry. Committing the new epoch durably BEFORE any item is
     * rewrapped under it is what makes a crash mid-rotation harmless -- the alternative (rewrap
     * first, record later) would leave items sealed under an epoch whose private key exists only
     * in this JVM's heap.
     */
    synchronized EpochKeyPair adoptAsCurrent(String epochId, HybridKem kem) {
        validateEpochId(epochId);
        loadIfPresent();
        String previousCurrent = currentEpochId;
        long generationBefore = generation;
        EpochKeyPair existing = entries.get(epochId);
        EpochKeyPair keys = existing != null ? existing : newEpochKeyPair(kem);
        entries.put(epochId, keys);
        currentEpochId = epochId;
        try {
            persist();
        } catch (RuntimeException e) {
            if (existing == null) entries.remove(epochId);
            currentEpochId = previousCurrent;
            generation = generationBefore;
            throw e;
        }
        return keys;
    }

    /**
     * Adds the ML-KEM half to an epoch that predates post-quantum being enabled.
     *
     * <p>Without this, turning on {@code enablePostQuantum} over an existing collection has no
     * effect at all: the recorded epoch has {@code mlkem == null}, so every "PQ" write silently
     * falls back to classical. Existing classical items stay readable -- their envelopes advertise
     * {@code kem_id=X25519} and are decapsulated as classical regardless of what the epoch now
     * holds. Returns the original pair unchanged if no upgrade is needed or possible.</p>
     */
    private EpochKeyPair upgradePqIfNeeded(String epochId, EpochKeyPair held, HybridKem kem) {
        // Gate on the STORED BYTES, not on `mlkem != null`. An epoch whose PQ half exists on disk
        // but could not be imported (no ML-KEM provider on this JVM) also has mlkem == null, and
        // minting over it would overwrite the surviving public key -- destroying every item sealed
        // under it even once the provider returns.
        if (held.hasStoredPqHalf() || held.mlkem != null || !kem.postQuantumAvailable()) return held;
        KeyPair pq = kem.generatePqKeyPair();
        EpochKeyPair upgraded = new EpochKeyPair(held.x25519, pq,
                pq.getPublic().getEncoded(), pq.getPrivate().getEncoded());
        long generationBefore = generation;
        entries.put(epochId, upgraded);
        try {
            persist();
        } catch (RuntimeException e) {
            entries.put(epochId, held);
            generation = generationBefore;
            log.warn("EpochKeystore: could not add the ML-KEM half to epoch {}: {}; "
                    + "writes stay classical.", epochId, e.toString());
            return held;
        }
        log.info("EpochKeystore: added the ML-KEM half to epoch {} (post-quantum was enabled after "
                + "the epoch was created).", epochId);
        return upgraded;
    }

    private EpochKeyPair newEpochKeyPair(HybridKem kem) {
        KeyPair x = kem.generateEpochKeyPair();
        KeyPair pq = null;
        byte[] pqPub = null;
        if (kem.postQuantumAvailable()) {
            pq = kem.generatePqKeyPair();
            pqPub = pq.getPublic().getEncoded();
        }
        return new EpochKeyPair(x, pq, pqPub, pq == null ? null : pq.getPrivate().getEncoded());
    }

    /** Epoch ids are length-prefixed with ONE byte on the wire, so >255 bytes would corrupt it. */
    private static String validateEpochId(String id) {
        if (id == null || id.isEmpty()) {
            throw new IllegalArgumentException("epoch id must be non-empty");
        }
        byte[] ascii = id.getBytes(StandardCharsets.US_ASCII);
        if (!new String(ascii, StandardCharsets.US_ASCII).equals(id)) {
            throw new IllegalArgumentException("epoch id must be US-ASCII: " + id);
        }
        if (ascii.length > 255) {
            throw new IllegalArgumentException("epoch id too long (" + ascii.length + " > 255)");
        }
        return id;
    }

    /** Returns the keypairs for {@code epochId}, generating + persisting them on first use. */
    synchronized EpochKeyPair getOrCreate(String epochId, HybridKem kem) {
        loadIfPresent();
        EpochKeyPair existing = entries.get(epochId);
        if (existing != null) return upgradePqIfNeeded(epochId, existing, kem);
        KeyPair x = kem.generateEpochKeyPair();
        KeyPair pq = null;
        byte[] pqPub = null;
        if (kem.postQuantumAvailable()) {
            pq = kem.generatePqKeyPair();
            pqPub = pq.getPublic().getEncoded();
        }
        EpochKeyPair fresh = new EpochKeyPair(x, pq, pqPub,
                pq == null ? null : pq.getPrivate().getEncoded());
        // Roll back on a failed persist. Without this the un-persisted epoch stays in `entries`,
        // and because loadIfPresent() short-circuits (or finds no keystore to reload from) the
        // caller's retry gets this same in-memory keypair back WITHOUT ever writing it. The write
        // then succeeds and the item is sealed under an epoch whose private key exists only in
        // this JVM's heap -- permanently undecryptable after restart. Restoring `generation` too,
        // because persist() increments it before attempting the write.
        long generationBefore = generation;
        entries.put(epochId, fresh);
        try {
            persist();
        } catch (RuntimeException e) {
            entries.remove(epochId);
            generation = generationBefore;
            throw e;
        }
        return fresh;
    }

    /**
     * Drops every epoch entry except {@code epochId} (forward-secrecy primitive); persists if
     * anything changed. This destroys epochs from earlier sessions that a single-step rotation
     * would leave alive, so a pre-rotation backup plus the current keystore can no longer
     * decapsulate any superseded envelope.
     */
    synchronized void retainOnly(String epochId) {
        loadIfPresent();
        // Refuse to "retain" an epoch we do not hold. retainAll(Set.of(unknown)) empties the map,
        // so this call would destroy EVERY epoch private key and persist an empty keystore --
        // making every item in the collection permanently undecryptable. rotateEpoch used to reach
        // exactly this state when its item enumeration came back empty. Fail loudly instead.
        if (epochId == null || !entries.containsKey(epochId)) {
            throw new IllegalStateException(
                    "EpochKeystore: refusing retainOnly(" + epochId + ") -- not a held epoch; "
                            + "retaining it would destroy every epoch key in the keystore.");
        }
        // Snapshot what is about to be dropped so a failed persist can roll back. Without the
        // rollback, a transient write failure left the superseded keys destroyed IN MEMORY while
        // the on-disk keystore still held them: every item under an old epoch became unreadable
        // for the rest of the process lifetime, contradicting rotateEpoch's documented contract
        // that false means "the old keys are still usable". Every other mutator here already
        // rolls back on a failed persist; this was the one that did not.
        Map<String, EpochKeyPair> removed = new LinkedHashMap<>();
        for (Map.Entry<String, EpochKeyPair> e : entries.entrySet()) {
            if (!epochId.equals(e.getKey())) removed.put(e.getKey(), e.getValue());
        }
        if (entries.keySet().retainAll(Set.of(epochId))) {
            try {
                persist();
            } catch (RuntimeException e) {
                entries.putAll(removed);
                throw e;
            }
            log.info("EpochKeystore: retained only epoch {}; destroyed all superseded epoch keys.",
                    epochId);
        }
    }

    synchronized Optional<EpochKeyPair> get(String epochId) {
        loadIfPresent();
        return Optional.ofNullable(entries.get(epochId));
    }

    // --------- internal: AES-GCM under pepper-derived KEK ---------

    private void persist() {
        if (refused) {
            // Writing now would fork a second keystore alongside the one we refused to load, and
            // the next load would delete the genuine snapshot as "superseded".
            throw new IllegalStateException(
                    "EpochKeystore: refusing to write -- the keystore was refused at load time as a "
                            + "possible rollback (generation below the anti-rollback floor). Restore "
                            + "the genuine keystore or re-provision the anchor before writing.");
        }
        // Next generation lives in the anchor's value space so the load-side floor comparison is
        // apples-to-apples. Without an anchor this reduces to the old generation++ behaviour.
        long floor = anchor != null ? anchor.read() : generation;
        generation = Math.max(generation, floor) + 1;
        byte[] plain = serialize();
        byte[] aead = null;
        try {
            try {
                aead = aeadEncrypt(deriveKek(provider.getPepper()), plain);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("EpochKeystore: AES-GCM encryption failed", e);
            }
            String body = Base64.getEncoder().encodeToString(aead);
            Map<String, String> attrs = new HashMap<>();
            attrs.put(ATTR_KIND, KIND_VALUE);
            // Create-then-delete: the previous keystore item must survive until the replacement
            // is durably written. The keystore is the only copy of the epoch private keys -- a
            // crash after a delete-first would make every KEM-wrapped item in the collection
            // permanently undecryptable. A crash between create and delete merely leaves a
            // superseded duplicate, which the next loadIfPresent detects (lower generation)
            // and removes.
            String previousPath = keystorePath;
            Optional<String> created = wrapped.createItem(LABEL, body, attrs);
            if (created.isEmpty()) {
                throw new IllegalStateException("EpochKeystore: persist failed -- createItem returned empty");
            }
            keystorePath = created.get();
            // Write-ahead: the new snapshot is durably written, so advance the anchor now. A crash
            // between the create above and this advance leaves generation ahead of the floor, which
            // the next load treats as a lost-advance and catches up -- never as a rollback.
            if (anchor != null) {
                anchor.advanceTo(generation);
            }
            if (previousPath != null && !wrapped.deleteItem(previousPath)) {
                log.warn("EpochKeystore: could not delete superseded keystore item {}; "
                        + "a stale duplicate remains until the next persist.", previousPath);
            }
        } finally {
            Arrays.fill(plain, (byte) 0);
            if (aead != null) Arrays.fill(aead, (byte) 0);
        }
    }

    private byte[] aeadEncrypt(byte[] kek, byte[] plain) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_LEN];
        new SecureRandom().nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        byte[] ct = c.doFinal(plain);
        Arrays.fill(kek, (byte) 0);
        ByteBuffer out = ByteBuffer.allocate(NONCE_LEN + ct.length);
        out.put(nonce);
        out.put(ct);
        return out.array();
    }

    private byte[] aeadDecrypt(byte[] kek, byte[] noncePlusCt) throws GeneralSecurityException {
        if (noncePlusCt.length < NONCE_LEN + 16) {
            throw new GeneralSecurityException("keystore body too short");
        }
        byte[] nonce = Arrays.copyOf(noncePlusCt, NONCE_LEN);
        byte[] ct = Arrays.copyOfRange(noncePlusCt, NONCE_LEN, noncePlusCt.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        try {
            return c.doFinal(ct);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
    }

    private static byte[] deriveKek(char[] pepper) {
        // Deterministic: same pepper → same KEK → keystore decryptable across JVM restarts.
        ByteBuffer enc = StandardCharsets.UTF_8.encode(CharBuffer.wrap(pepper));
        byte[] pepperBytes = new byte[enc.remaining()];
        enc.get(pepperBytes);
        try {
            return Hkdf.extractThenExpandSha256(KEK_FIXED_SALT, pepperBytes, KEK_INFO, KEK_LEN);
        } finally {
            Arrays.fill(pepperBytes, (byte) 0);
            Arrays.fill(pepper, '\0');
        }
    }

    // --------- internal: serialise / deserialise the entry map ---------

    /**
     * The ML-KEM private bytes to write for this entry.
     *
     * <p>Prefers the retained encoding over re-encoding the {@link KeyPair}, so an entry we could
     * not import round-trips byte-for-byte instead of being written as a zero-length private (which
     * destroyed it permanently). Always returns a fresh array: {@link #serialize} zeroes what it
     * gets, and that must never reach the stored field.</p>
     */
    private static byte[] mlkemPrivBytes(EpochKeyPair e) {
        if (e.mlkemPrivEncoded != null) return e.mlkemPrivEncoded.clone();
        return e.mlkem == null ? new byte[0] : e.mlkem.getPrivate().getEncoded();
    }

    private byte[] serialize() {
        if (entries.size() > 65535) {
            // n_entries is a 2-byte field read back with Short.toUnsignedInt, so 65536 entries
            // would write n = 0: deserialize would return an empty map and the next persist would
            // make that loss permanent. Fail loudly instead of silently dropping every key.
            throw new IllegalStateException(
                    "EpochKeystore: too many epochs to serialize (" + entries.size() + " > 65535)");
        }
        byte[] cur = currentEpochId == null
                ? new byte[0]
                : currentEpochId.getBytes(StandardCharsets.US_ASCII);
        // Encode every entry ONCE, up front. An earlier version computed the private encodings
        // twice -- once to total the lengths, once to write them -- and only the write loop zeroed
        // them, so each persist left a full X25519 private plus an ML-KEM private clone as heap
        // garbage until GC. Encoding once means there is exactly one copy to erase, and the
        // try/finally below erases it on every path.
        List<byte[]> encoded = new ArrayList<>(entries.size() * 5);
        try {
            int total = 1 + 8 + 1 + cur.length + 2;
            for (Map.Entry<String, EpochKeyPair> e : entries.entrySet()) {
                // Add each buffer the moment it exists -- never batch the adds after the computes.
                // x25519PublicEncoded/mlkemPrivBytes sit between the private-key encodings, so a
                // throw there would otherwise leave an already-computed private key outside the
                // list, invisible to the finally below and never zeroed.
                byte[] id = e.getKey().getBytes(StandardCharsets.US_ASCII);
                encoded.add(id);
                byte[] xPriv = e.getValue().x25519.getPrivate().getEncoded();
                encoded.add(xPriv);
                byte[] xPub = x25519PublicEncoded(e.getValue());
                encoded.add(xPub);
                byte[] mPriv = mlkemPrivBytes(e.getValue());
                encoded.add(mPriv);
                byte[] mPub = e.getValue().mlkemPubEncoded == null ? new byte[0] : e.getValue().mlkemPubEncoded;
                encoded.add(mPub);
                total += 1 + id.length + 2 + xPriv.length + 2 + xPub.length + 2 + mPriv.length + 2 + mPub.length;
            }
            ByteBuffer buf = ByteBuffer.allocate(total);
            buf.put(VERSION_3);
            buf.putLong(generation);
            buf.put((byte) cur.length);
            buf.put(cur);
            buf.putShort((short) entries.size());
            for (int i = 0; i < encoded.size(); i += 5) {
                byte[] id = encoded.get(i);
                byte[] xPriv = encoded.get(i + 1);
                byte[] xPub = encoded.get(i + 2);
                byte[] mPriv = encoded.get(i + 3);
                byte[] mPub = encoded.get(i + 4);
                buf.put((byte) id.length);
                buf.put(id);
                buf.putShort((short) xPriv.length).put(xPriv);
                buf.putShort((short) xPub.length).put(xPub);
                buf.putShort((short) mPriv.length).put(mPriv);
                buf.putShort((short) mPub.length).put(mPub);
            }
            return buf.array();
        } finally {
            // Indices 1 and 3 of each 5-tuple are the private encodings. mPub/xPub are public and
            // mlkemPubEncoded is the LIVE field, not a copy -- zeroing it would corrupt the entry.
            // Iterate per element, not per complete tuple: an exception mid-entry leaves a partial
            // tuple whose already-added private encoding must still be erased.
            for (int i = 0; i < encoded.size(); i++) {
                if (i % 5 == 1 || i % 5 == 3) Arrays.fill(encoded.get(i), (byte) 0);
            }
        }
    }

    /** X25519 public SPKI, or empty for an epoch loaded from a V1 keystore that never stored it. */
    private static byte[] x25519PublicEncoded(EpochKeyPair pair) {
        return pair.x25519.getPublic() == null ? new byte[0] : pair.x25519.getPublic().getEncoded();
    }

    /** One decrypted keystore snapshot: its persist generation and the epoch entries. */
    private record Parsed(long generation, String currentEpochId, Map<String, EpochKeyPair> entries) {}

    private Parsed deserialize(byte[] in) {
        ByteBuffer buf = ByteBuffer.wrap(in);
        byte version = buf.get();
        boolean hasX25519Pub;
        boolean hasCurrent;
        if (version == VERSION_3) {
            hasX25519Pub = true;
            hasCurrent = true;
        } else if (version == VERSION_2) {
            hasX25519Pub = true;
            hasCurrent = false;
        } else if (version == VERSION_1) {
            hasX25519Pub = false; // legacy: no stored X25519 public -> loads with a null public
            hasCurrent = false;
        } else {
            throw new IllegalArgumentException("unsupported keystore version: " + version);
        }
        long gen = buf.getLong();
        String cur = null;
        if (hasCurrent) {
            int curLen = Byte.toUnsignedInt(buf.get());
            byte[] curBytes = new byte[curLen];
            buf.get(curBytes);
            if (curLen > 0) cur = new String(curBytes, StandardCharsets.US_ASCII);
        }
        int n = Short.toUnsignedInt(buf.getShort());
        Map<String, EpochKeyPair> parsed = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) {
            int idLen = Byte.toUnsignedInt(buf.get());
            byte[] id = new byte[idLen]; buf.get(id);
            int xPrivLen = Short.toUnsignedInt(buf.getShort());
            byte[] xPriv = new byte[xPrivLen]; buf.get(xPriv);
            byte[] xPub = new byte[0];
            if (hasX25519Pub) {
                int xPubLen = Short.toUnsignedInt(buf.getShort());
                xPub = new byte[xPubLen]; buf.get(xPub);
            }
            int mPrivLen = Short.toUnsignedInt(buf.getShort());
            byte[] mPriv = new byte[mPrivLen]; buf.get(mPriv);
            int mPubLen = Short.toUnsignedInt(buf.getShort());
            byte[] mPub = new byte[mPubLen]; buf.get(mPub);

            KeyPair x;
            try {
                // With the public present (V2) the epoch is fully usable, including for writes;
                // without it (legacy V1) only the private is available -- reads still work.
                x = xPub.length > 0
                        ? HybridKem.importX25519KeyPair(xPriv, xPub)
                        : HybridKem.importX25519KeyPairFromPkcs8(xPriv);
            } finally {
                Arrays.fill(xPriv, (byte) 0);
            }
            KeyPair m = null;
            byte[] mPubKept = mPub.length == 0 ? null : mPub;
            byte[] mPrivKept = null;
            if (mPrivLen > 0 && mPubLen > 0) {
                // Retain the raw bytes REGARDLESS of whether the import succeeds. A failure here is
                // almost always "this JVM has no ML-KEM provider", which is transient; dropping the
                // bytes would turn it into permanent destruction on the next persist.
                mPrivKept = mPriv.clone();
                try {
                    m = mlKemImporter.importKeyPair(mPriv, mPub);
                } catch (RuntimeException e) {
                    log.warn("EpochKeystore: ML-KEM keypair for an epoch could not be re-imported ({}). "
                            + "Its stored key material is preserved untouched, so PQ items under that "
                            + "epoch stay unreadable only until the provider is available again.",
                            e.toString());
                } finally {
                    Arrays.fill(mPriv, (byte) 0);
                }
            } else if (mPrivLen > 0) {
                // Malformed/legacy: a private with no public. Unusable, but still zero it rather
                // than leaving a plaintext PQ private lying in a heap array.
                Arrays.fill(mPriv, (byte) 0);
            }
            parsed.put(new String(id, StandardCharsets.US_ASCII),
                    new EpochKeyPair(x, m, mPubKept, mPrivKept));
            // The EpochKeyPair constructor CLONES mlkemPrivEncoded, so this local is a spare copy
            // of an ML-KEM private key -- one extra piece of heap garbage per entry per load if
            // left unzeroed.
            if (mPrivKept != null) Arrays.fill(mPrivKept, (byte) 0);
        }
        return new Parsed(gen, cur, parsed);
    }

    /** For tests: direct access to in-memory entry count. */
    synchronized int sizeForTest() { return entries.size(); }
}
