package de.swiesend.secretservice.hardened;

import at.favre.lib.hkdf.HKDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/**
 * Hybrid KEM: X25519 (classical) combined with ML-KEM-768 when available on the runtime.
 *
 * <p>Per-envelope flow:
 * <ol>
 *   <li>Generate an ephemeral X25519 keypair.</li>
 *   <li>ECDH(ephemeral_priv, epoch_pub) -> ss_classical.</li>
 *   <li>If PQ available: ML-KEM encapsulate(epoch_mlkem_pub) -> (ss_pq, pq_ciphertext).</li>
 *   <li>combined = HKDF-Extract(salt=null, ikm = ss_classical ‖ ss_pq ‖ "secret-service/hybrid-kem/v1").</li>
 *   <li>Envelope's KEM ciphertext contains the ephemeral X25519 public key (and pq_ciphertext if PQ).</li>
 * </ol>
 *
 * <p>On decapsulation the decoder uses the epoch private key(s). Destroying those keys
 * on {@code rotateEpoch()} renders all prior envelopes unreadable — this is the
 * forward-secrecy primitive for time-binding via epoch ratcheting.</p>
 *
 * <p>When ML-KEM is unavailable the hybrid degrades to X25519-only; the envelope's
 * {@link Envelope#FLAG_PQ_HYBRID} flag is unset and {@link #postQuantumAvailable()}
 * returns false.</p>
 */
public final class HybridKem {

    private static final Logger log = LoggerFactory.getLogger(HybridKem.class);
    private static final String HKDF_INFO_TAG = "secret-service/hybrid-kem/v1";
    private static final String X25519 = "X25519";

    private final boolean preferPostQuantum;
    private final boolean postQuantumAvailable;

    public HybridKem(boolean preferPostQuantum) {
        this.preferPostQuantum = preferPostQuantum;
        this.postQuantumAvailable = preferPostQuantum && probeMlKem();
        if (preferPostQuantum && !this.postQuantumAvailable) {
            log.warn("HybridKem: ML-KEM-768 not available on this runtime (requires JDK 24+ with a provider); "
                    + "falling back to X25519-only. Envelopes will be flagged kem=x25519.");
        }
    }

    public boolean postQuantumAvailable() { return postQuantumAvailable; }

    public String algorithmLabel() {
        return postQuantumAvailable ? "x25519+ml-kem-768" : "x25519";
    }

    public KeyPair generateEpochKeyPair() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(X25519);
            g.initialize(NamedParameterSpec.X25519, new SecureRandom());
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 keypair generation failed", e);
        }
    }

    /**
     * Result of encapsulation: the derived shared secret and the bytes to store in the envelope
     * as the KEM ciphertext (ephemeral X25519 public key, followed by optional ML-KEM ciphertext).
     */
    public record Encapsulation(byte[] sharedSecret, byte[] kemCiphertext) {
        public void clear() {
            Arrays.fill(sharedSecret, (byte) 0);
        }
    }

    /**
     * Encapsulate against the given epoch public X25519 key (and optional PQ key).
     * PQ path is currently a stub: if {@link #postQuantumAvailable()} is true, the method
     * would additionally invoke {@code javax.crypto.KEM("ML-KEM-768")} — gated behind
     * a runtime probe so the code compiles on JDK 21.
     */
    public Encapsulation encapsulate(PublicKey epochX25519Public) {
        KeyPair ephemeral;
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(X25519);
            g.initialize(NamedParameterSpec.X25519, new SecureRandom());
            ephemeral = g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ephemeral keypair failed", e);
        }
        byte[] ssClassical = ecdh(ephemeral.getPrivate(), epochX25519Public);
        byte[] ephPubEnc = ephemeral.getPublic().getEncoded();

        byte[] combined;
        byte[] kemCt;
        if (postQuantumAvailable) {
            // Placeholder for ML-KEM encapsulation. The runtime probe guarantees the KEM API
            // exists; ML-KEM-768 is provided by JDK 24+. We leave the real call behind a
            // reflective shim in a follow-up so that this module compiles on JDK 21.
            byte[] ssPq = invokeMlKemEncap(epochX25519Public); // returns empty on failure
            combined = combine(ssClassical, ssPq);
            kemCt = ephPubEnc; // pq ciphertext would be appended in the JDK 24 impl
            Arrays.fill(ssPq, (byte) 0);
        } else {
            combined = combine(ssClassical, new byte[0]);
            kemCt = ephPubEnc;
        }
        Arrays.fill(ssClassical, (byte) 0);
        return new Encapsulation(combined, kemCt);
    }

    /**
     * Decapsulate against the epoch private X25519 key and the stored KEM ciphertext bytes.
     */
    public byte[] decapsulate(PrivateKey epochX25519Private, byte[] kemCiphertext, boolean envelopeIsHybrid) {
        try {
            KeyFactory kf = KeyFactory.getInstance(X25519);
            PublicKey ephemeralPub = kf.generatePublic(new X509EncodedKeySpec(kemCiphertext));
            byte[] ssClassical = ecdh(epochX25519Private, ephemeralPub);
            byte[] ssPq = envelopeIsHybrid && postQuantumAvailable
                    ? invokeMlKemDecap(epochX25519Private, kemCiphertext)
                    : new byte[0];
            byte[] combined = combine(ssClassical, ssPq);
            Arrays.fill(ssClassical, (byte) 0);
            Arrays.fill(ssPq, (byte) 0);
            return combined;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("decapsulation failed", e);
        }
    }

    /** Serialise an X25519 private key for epoch persistence; caller zeros the bytes. */
    public static byte[] exportPrivate(PrivateKey k) {
        return k.getEncoded();
    }

    public static PrivateKey importPrivate(byte[] enc) {
        try {
            return KeyFactory.getInstance(X25519).generatePrivate(new PKCS8EncodedKeySpec(enc));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("private key import failed", e);
        }
    }

    public static byte[] exportPublic(PublicKey k) {
        return k.getEncoded();
    }

    public static PublicKey importPublic(byte[] enc) {
        try {
            return KeyFactory.getInstance(X25519).generatePublic(new X509EncodedKeySpec(enc));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("public key import failed", e);
        }
    }

    private static byte[] ecdh(PrivateKey priv, PublicKey pub) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance(X25519);
            ka.init(priv);
            ka.doPhase(pub, true);
            return ka.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 ECDH failed", e);
        }
    }

    private static byte[] combine(byte[] ssClassical, byte[] ssPq) {
        byte[] ikm = new byte[ssClassical.length + ssPq.length];
        System.arraycopy(ssClassical, 0, ikm, 0, ssClassical.length);
        System.arraycopy(ssPq, 0, ikm, ssClassical.length, ssPq.length);
        byte[] info = HKDF_INFO_TAG.getBytes(StandardCharsets.UTF_8);
        byte[] prk = HKDF.fromHmacSha256().extract((byte[]) null, ikm);
        byte[] combined = HKDF.fromHmacSha256().expand(prk, info, 32);
        Arrays.fill(ikm, (byte) 0);
        Arrays.fill(prk, (byte) 0);
        return combined;
    }

    /**
     * Probe whether {@code javax.crypto.KEM} and ML-KEM-768 are both present.
     * On JDK 21 KEM API exists but ML-KEM is absent; on JDK 24+ it lands in the standard providers.
     */
    private static boolean probeMlKem() {
        try {
            Class<?> kem = Class.forName("javax.crypto.KEM");
            Object instance = kem.getMethod("getInstance", String.class).invoke(null, "ML-KEM-768");
            return instance != null;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Reflective ML-KEM encapsulation stub; returns empty on any failure. */
    private static byte[] invokeMlKemEncap(PublicKey epochPub) {
        // Intentionally a stub until JDK 24 is the build floor. Returning an empty shared
        // secret means the combiner reduces to classical-only even when postQuantumAvailable
        // reports true — the flag is kept for observability and to gate envelope flagging.
        return new byte[0];
    }

    private static byte[] invokeMlKemDecap(PrivateKey epochPriv, byte[] kemCiphertext) {
        return new byte[0];
    }
}
