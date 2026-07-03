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
 * <p>Real PQ wiring needs the KEM private key on read. We can't derive it from the
 * pepper alone (then it would not survive {@link HardenedCollection#rotateEpoch}
 * destroying it), and we don't want yet another out-of-band file. Storing the
 * keystore as a hardened-but-special item in the same collection means the same
 * backup that captures the user's secrets also captures the epoch keys -- which
 * is the realistic operational story (lose the keyring file → lose access).
 * The keystore is encrypted; the ciphertext-at-rest is opaque to the daemon,
 * the same as any other hardened item.</p>
 *
 * <h3>Forward secrecy via destruction</h3>
 * <p>{@link #removeEpoch(String)} drops a (epochId → keypairs) entry from the
 * internal map and re-persists the keystore. After {@link HardenedCollection#rotateEpoch}
 * has rewrapped all items under the new epoch and removed the old epoch's entry,
 * old envelopes (e.g. captured from a backup taken pre-rotation) cannot be
 * decapsulated even by an attacker who later compromises the host -- the private
 * key is gone. This is the class-D / HNDL defense the {@code kem_id} byte
 * advertises.</p>
 *
 * <h3>Wire format (inside the AES-256-GCM ciphertext)</h3>
 * <pre>
 * version(1)=0x02 | generation(8) | n_entries(2) |
 *   ( id_len(1) | id[id_len] | x25519_priv_len(2) | x25519_priv[..] | x25519_pub_len(2) | x25519_pub[..] |
 *     mlkem_priv_len(2) | mlkem_priv[..] | mlkem_pub_len(2) | mlkem_pub[..] ) repeated
 * </pre>
 *
 * <p>{@code generation} increments on every persist. Persisting is create-then-delete, so
 * a crash can leave two decryptable keystore items; on load the highest generation wins
 * and provably-superseded duplicates are deleted. Picking by generation (not item order)
 * matters: loading a stale keystore would either resurrect epoch keys that
 * {@link #removeEpoch} destroyed (breaking forward secrecy) or drop keys created
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
    private static final byte VERSION_1 = 0x01;
    private static final byte VERSION_2 = 0x02;
    private static final int NONCE_LEN = 12;
    private static final int KEK_LEN = 32; // AES-256
    private static final int TAG_BITS = 128;
    private static final byte[] KEK_INFO = "secret-service/hardened/epoch-keystore-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEK_FIXED_SALT = "epoch-keystore-salt-v1".getBytes(StandardCharsets.UTF_8);

    static final class EpochKeyPair {
        final KeyPair x25519;
        final KeyPair mlkem;            // null when PQ is not used for this epoch
        final byte[] mlkemPubEncoded;   // cached so we don't re-encode on every encap

        EpochKeyPair(KeyPair x25519, KeyPair mlkem, byte[] mlkemPubEncoded) {
            this.x25519 = x25519;
            this.mlkem = mlkem;
            this.mlkemPubEncoded = mlkemPubEncoded == null ? null : mlkemPubEncoded.clone();
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
        Optional<List<String>> paths = wrapped.getItems(Map.of(ATTR_KIND, KIND_VALUE));
        if (paths.isEmpty() || paths.get().isEmpty()) {
            return;
        }
        // An interrupted persist (create-then-delete) can leave two decryptable keystore
        // items; a stale keystore written under a different pepper is also possible. Decrypt
        // every candidate and load the highest generation -- item order proves nothing.
        List<String> candidates = paths.get();
        if (candidates.size() > 1) {
            log.warn("EpochKeystore: found {} keystore items; loading the highest generation.",
                    candidates.size());
        }
        String bestPath = null;
        Parsed best = null;
        List<String> superseded = new ArrayList<>();
        for (String path : candidates) {
            Optional<Map<String, String>> attrs = wrapped.getAttributes(path);
            if (attrs.isEmpty() || !KIND_VALUE.equals(attrs.get().get(ATTR_KIND))) continue;
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
                if (bestPath != null) superseded.add(bestPath);
                best = parsed;
                bestPath = path;
            } else {
                superseded.add(path);
            }
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
                        + "fail closed.", best.generation, floor);
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

    /** Returns the keypairs for {@code epochId}, generating + persisting them on first use. */
    synchronized EpochKeyPair getOrCreate(String epochId, HybridKem kem) {
        loadIfPresent();
        EpochKeyPair existing = entries.get(epochId);
        if (existing != null) return existing;
        KeyPair x = kem.generateEpochKeyPair();
        KeyPair pq = null;
        byte[] pqPub = null;
        if (kem.postQuantumAvailable()) {
            pq = kem.generatePqKeyPair();
            pqPub = pq.getPublic().getEncoded();
        }
        EpochKeyPair fresh = new EpochKeyPair(x, pq, pqPub);
        entries.put(epochId, fresh);
        persist();
        return fresh;
    }

    /** Removes an epoch entry (forward-secrecy primitive); persists the new state. */
    synchronized void removeEpoch(String epochId) {
        loadIfPresent();
        if (entries.remove(epochId) != null) {
            persist();
        }
    }

    /**
     * Drops every epoch entry except {@code epochId} (forward-secrecy primitive); persists if
     * anything changed. Unlike {@link #removeEpoch}, this also destroys epochs from earlier
     * sessions that a single-step rotation would leave alive, so a pre-rotation backup plus the
     * current keystore can no longer decapsulate any superseded envelope.
     */
    synchronized void retainOnly(String epochId) {
        loadIfPresent();
        if (entries.keySet().retainAll(Set.of(epochId))) {
            log.info("EpochKeystore: retained only epoch {}; destroyed all superseded epoch keys.",
                    epochId);
            persist();
        }
    }

    synchronized Optional<EpochKeyPair> get(String epochId) {
        loadIfPresent();
        return Optional.ofNullable(entries.get(epochId));
    }

    // --------- internal: AES-GCM under pepper-derived KEK ---------

    private void persist() {
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
            byte[] prk = HKDF.fromHmacSha256().extract(KEK_FIXED_SALT, pepperBytes);
            try {
                return HKDF.fromHmacSha256().expand(prk, KEK_INFO, KEK_LEN);
            } finally {
                Arrays.fill(prk, (byte) 0);
            }
        } finally {
            Arrays.fill(pepperBytes, (byte) 0);
            Arrays.fill(pepper, '\0');
        }
    }

    // --------- internal: serialise / deserialise the entry map ---------

    private byte[] serialize() {
        // Compute total size first
        int total = 1 + 8 + 2;
        for (Map.Entry<String, EpochKeyPair> e : entries.entrySet()) {
            byte[] id = e.getKey().getBytes(StandardCharsets.US_ASCII);
            byte[] xPriv = e.getValue().x25519.getPrivate().getEncoded();
            byte[] xPub = x25519PublicEncoded(e.getValue());
            byte[] mPriv = e.getValue().mlkem == null ? new byte[0] : e.getValue().mlkem.getPrivate().getEncoded();
            byte[] mPub = e.getValue().mlkemPubEncoded == null ? new byte[0] : e.getValue().mlkemPubEncoded;
            total += 1 + id.length + 2 + xPriv.length + 2 + xPub.length + 2 + mPriv.length + 2 + mPub.length;
        }
        ByteBuffer buf = ByteBuffer.allocate(total);
        buf.put(VERSION_2);
        buf.putLong(generation);
        buf.putShort((short) entries.size());
        for (Map.Entry<String, EpochKeyPair> e : entries.entrySet()) {
            byte[] id = e.getKey().getBytes(StandardCharsets.US_ASCII);
            byte[] xPriv = e.getValue().x25519.getPrivate().getEncoded();
            byte[] xPub = x25519PublicEncoded(e.getValue());
            byte[] mPriv = e.getValue().mlkem == null ? new byte[0] : e.getValue().mlkem.getPrivate().getEncoded();
            byte[] mPub = e.getValue().mlkemPubEncoded == null ? new byte[0] : e.getValue().mlkemPubEncoded;
            buf.put((byte) id.length);
            buf.put(id);
            buf.putShort((short) xPriv.length).put(xPriv);
            buf.putShort((short) xPub.length).put(xPub);
            buf.putShort((short) mPriv.length).put(mPriv);
            buf.putShort((short) mPub.length).put(mPub);
            Arrays.fill(xPriv, (byte) 0);
            Arrays.fill(mPriv, (byte) 0);
        }
        return buf.array();
    }

    /** X25519 public SPKI, or empty for an epoch loaded from a V1 keystore that never stored it. */
    private static byte[] x25519PublicEncoded(EpochKeyPair pair) {
        return pair.x25519.getPublic() == null ? new byte[0] : pair.x25519.getPublic().getEncoded();
    }

    /** One decrypted keystore snapshot: its persist generation and the epoch entries. */
    private record Parsed(long generation, Map<String, EpochKeyPair> entries) {}

    private Parsed deserialize(byte[] in) {
        ByteBuffer buf = ByteBuffer.wrap(in);
        byte version = buf.get();
        boolean hasX25519Pub;
        if (version == VERSION_2) {
            hasX25519Pub = true;
        } else if (version == VERSION_1) {
            hasX25519Pub = false; // legacy: no stored X25519 public -> loads with a null public
        } else {
            throw new IllegalArgumentException("unsupported keystore version: " + version);
        }
        long gen = buf.getLong();
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
            if (mPrivLen > 0 && mPubLen > 0) {
                try {
                    m = HybridKem.importMlKemKeyPair(mPriv, mPub);
                } catch (RuntimeException e) {
                    log.warn("EpochKeystore: ML-KEM keypair could not be re-imported: {}", e.toString());
                } finally {
                    Arrays.fill(mPriv, (byte) 0);
                }
            }
            parsed.put(new String(id, StandardCharsets.US_ASCII), new EpochKeyPair(x, m, mPubKept));
        }
        return new Parsed(gen, parsed);
    }

    /** For tests: direct access to in-memory entry count. */
    synchronized int sizeForTest() { return entries.size(); }
}
