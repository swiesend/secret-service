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

    private volatile String epochId;

    private HardenedCollection(Builder b) {
        this.wrapped = Objects.requireNonNull(b.wrapped, "wrapped collection");
        this.provider = Objects.requireNonNull(b.provider, "key material provider");
        this.acknowledgeSecurityTheater = b.acknowledgeSecurityTheater;
        this.kem = new HybridKem(b.enablePostQuantum);

        ThreatCoverage tc = provider.threatCoverage();
        if (tc.isSecurityTheaterVsSameUid() && !acknowledgeSecurityTheater) {
            throw new SecurityTheaterException(
                "KeyMaterialProvider " + provider.getClass().getSimpleName()
                        + " declares same-UID threat coverage=NONE: " + tc.rationale()
                        + " If this is a CI/dev build, call .acknowledgeSecurityTheater(true) on the builder."
            );
        }
        this.epochId = b.epochId != null ? b.epochId : newEpochId();
    }

    public static Builder builder(CollectionInterface wrapped) {
        return new Builder(wrapped);
    }

    public static final class Builder {
        private final CollectionInterface wrapped;
        private KeyMaterialProvider provider;
        private boolean acknowledgeSecurityTheater = false;
        private boolean enablePostQuantum = false;
        private String epochId;

        Builder(CollectionInterface wrapped) { this.wrapped = wrapped; }

        public Builder keyMaterial(KeyMaterialProvider p) { this.provider = p; return this; }
        public Builder acknowledgeSecurityTheater(boolean b) { this.acknowledgeSecurityTheater = b; return this; }
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
        String envelopeB64;
        try {
            dek = deriveDek(pepper, totpCode, salt, epochBytes, itemId.getBytes(StandardCharsets.US_ASCII));
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

            Envelope env = new Envelope(Envelope.VERSION_1, flags, kemId, salt, epochBytes, nonce, aeadCt);
            envelopeB64 = Base64.getEncoder().encodeToString(env.toBytes());
        } finally {
            Arrays.fill(plaintext, (byte) 0);
            if (dek != null) Arrays.fill(dek, (byte) 0);
            Arrays.fill(pepper, '\0');
            Arrays.fill(totpCode, (byte) 0);
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
    public <R> Optional<R> withSecret(String objectPath, Function<char[], R> callback) {
        Objects.requireNonNull(objectPath, "objectPath");
        Objects.requireNonNull(callback, "callback");

        Optional<Map<String, String>> attrs = wrapped.getAttributes(objectPath);
        if (attrs.isEmpty() || !ATTR_VERSION_V1.equals(attrs.get().get(ATTR_VERSION))) {
            log.warn("withSecret: item {} is not a hardened v1 item (missing {}); refusing to expose plaintext.",
                    objectPath, ATTR_VERSION);
            return Optional.empty();
        }

        return wrapped.withSecret(objectPath, envelopeChars -> {
            byte[] envelopeBytes;
            try {
                envelopeBytes = Base64.getDecoder().decode(new String(envelopeChars));
            } catch (IllegalArgumentException e) {
                log.warn("withSecret: envelope for {} is not valid base64", objectPath);
                return null;
            }
            if (!Envelope.looksLikeEnvelope(envelopeBytes)) {
                Arrays.fill(envelopeBytes, (byte) 0);
                log.warn("withSecret: envelope for {} is missing SSv1 magic", objectPath);
                return null;
            }
            Envelope env;
            try {
                env = Envelope.fromBytes(envelopeBytes);
            } catch (RuntimeException e) {
                Arrays.fill(envelopeBytes, (byte) 0);
                log.warn("withSecret: envelope parse failed for {}: {}", objectPath, e.getMessage());
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
        // We need items in this collection; iterate via empty-attribute query.
        Optional<List<String>> paths = wrapped.getItems(Map.of());
        if (paths.isEmpty()) return Optional.empty();
        Map<String, char[]> decoded = new LinkedHashMap<>();
        try {
            for (String path : paths.get()) {
                withSecret(path, secret -> { decoded.put(path, secret.clone()); return Boolean.TRUE; });
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
        // Rewrap every hardened item under the new epoch.
        Optional<List<String>> paths = wrapped.getItems(Map.of(ATTR_VERSION, ATTR_VERSION_V1));
        if (paths.isEmpty()) {
            this.epochId = next;
            return true;
        }
        this.epochId = next;
        boolean allOk = true;
        for (String path : paths.get()) {
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
                    wrapped.deleteItem(path);
                    Optional<String> created = createItem(label, CharBuffer.wrap(plain), oldAttrs);
                    return created.isPresent();
                } finally {
                    Arrays.fill(plain, '\0');
                }
            }).orElse(Boolean.FALSE);
            allOk &= ok;
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
            dek = deriveDek(pepper, totpCode, env.salt(), env.epochId(),
                    itemId.getBytes(StandardCharsets.US_ASCII));
            plain = aeadDecrypt(dek, env.nonce(), env.aeadCiphertext(),
                    associatedData(env.salt(), env.epochId(), itemId));
            return utf8ToChars(plain);
        } catch (GeneralSecurityException e) {
            log.warn("decrypt: AEAD failure for {}: {}", objectPath, e.getMessage());
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

    private static byte[] deriveDek(char[] pepper, byte[] totpCode, byte[] salt, byte[] epoch, byte[] itemId) {
        byte[] pepperBytes = charsToUtf8(CharBuffer.wrap(pepper));
        try {
            byte[] prk = HKDF.fromHmacSha256().extract(salt, pepperBytes);
            byte[] info = buildInfo(totpCode, epoch, itemId);
            byte[] dek = HKDF.fromHmacSha256().expand(prk, info, AEAD_KEY_LEN);
            Arrays.fill(prk, (byte) 0);
            Arrays.fill(info, (byte) 0);
            return dek;
        } finally {
            Arrays.fill(pepperBytes, (byte) 0);
        }
    }

    private static byte[] buildInfo(byte[] totpCode, byte[] epoch, byte[] itemId) {
        byte[] tag = HKDF_INFO_TAG.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(tag.length + 2 + totpCode.length + 2 + epoch.length + 2 + itemId.length);
        buf.put(tag);
        buf.putShort((short) totpCode.length).put(totpCode);
        buf.putShort((short) epoch.length).put(epoch);
        buf.putShort((short) itemId.length).put(itemId);
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
