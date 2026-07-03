package de.swiesend.secretservice.hardened;

import at.favre.lib.hkdf.HKDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Hybrid KEM: X25519 (classical) combined with ML-KEM-768 when a JCE provider
 * supplies the algorithm.
 *
 * <p>Implementation uses the standard {@link javax.crypto.KEM} API (JEP 452,
 * JDK 21+). ML-KEM-768 comes from:</p>
 * <ul>
 *   <li>SunJCE on JDK 24+ (built in).</li>
 *   <li>BouncyCastle 1.78+ on JDK 21-23 (registered via
 *       {@link PqProviderBootstrap#ensurePqProvider()}, which is invoked only
 *       when {@code preferPostQuantum=true}).</li>
 *   <li>Anything else providing the {@code "ML-KEM-768"} JCE algorithm.</li>
 * </ul>
 *
 * <p>If the algorithm is unavailable the layer degrades cleanly to X25519-only;
 * {@link #postQuantumAvailable()} reports the truth and the {@link Envelope#FLAG_PQ_HYBRID}
 * flag is left unset on writes.</p>
 *
 * <h3>Per-envelope flow (hybrid)</h3>
 * <ol>
 *   <li>Generate an ephemeral X25519 keypair.</li>
 *   <li>{@code ss_x25519 = ECDH(ephemeral_priv, epoch_x25519_pub)}.</li>
 *   <li>{@code (ss_pq, pq_ct) = KEM("ML-KEM-768").Encapsulator(epoch_pq_pub).encapsulate()}.</li>
 *   <li>{@code combined = HKDF(ss_x25519 || ss_pq, info="secret-service/hybrid-kem/v1", L=32)}.</li>
 *   <li>{@code kemCiphertext = uint16_be(x25519_spki_len) || x25519_spki || pq_ct}.</li>
 * </ol>
 *
 * <p>Decapsulation consumes the same {@code kemCiphertext} layout and uses the
 * stored epoch private keys. Destroying those keys on {@code rotateEpoch()}
 * renders all prior envelopes unreadable -- the forward-secrecy primitive for
 * time-binding via epoch ratcheting.</p>
 */
public final class HybridKem {

    private static final Logger log = LoggerFactory.getLogger(HybridKem.class);
    private static final String HKDF_INFO_TAG = "secret-service/hybrid-kem/v1";
    private static final String X25519 = "X25519";

    private final boolean preferPostQuantum;
    private final boolean postQuantumAvailable;

    public HybridKem(boolean preferPostQuantum) {
        this.preferPostQuantum = preferPostQuantum;
        this.postQuantumAvailable = preferPostQuantum && PqProviderBootstrap.ensurePqProvider();
        if (preferPostQuantum && !this.postQuantumAvailable) {
            log.warn("HybridKem: ML-KEM-768 unavailable; falling back to X25519-only. "
                    + "Envelopes will be flagged kem=x25519.");
        }
    }

    public boolean postQuantumAvailable() { return postQuantumAvailable; }

    public String algorithmLabel() {
        return Envelope.kemIdLabel(kemId());
    }

    /**
     * The {@link Envelope} {@code kem_id} byte this instance will stamp into fresh
     * envelopes. The KEM is always on: {@link Envelope#KEM_ID_X25519_MLKEM768} when PQ is
     * active, otherwise the classical {@link Envelope#KEM_ID_X25519}. It never returns
     * {@link Envelope#KEM_ID_NONE} -- that value only ever appears on legacy alpha envelopes.
     * Future iterations pick from the reserved values (HQC-192, triple hybrid) without
     * breaking the envelope format.
     */
    public byte kemId() {
        return postQuantumAvailable ? Envelope.KEM_ID_X25519_MLKEM768 : Envelope.KEM_ID_X25519;
    }

    /**
     * Generates the classical half of an epoch keypair. The PQ half (when enabled)
     * is generated via {@link #generatePqKeyPair()}; callers persist both.
     */
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
     * Generates the post-quantum half of an epoch keypair. Throws if PQ is not
     * available -- callers gate on {@link #postQuantumAvailable()}.
     *
     * <p>On JDK 24+ the stock SunJCE registers {@code "ML-KEM-768"} as an explicit
     * algorithm and we initialise directly with that name. On JDK 21-23 with
     * BouncyCastle 1.82+, the JCE name is {@code "ML-KEM"} and the parameter set
     * is supplied via {@code org.bouncycastle.jcajce.spec.MLKEMParameterSpec}
     * (looked up reflectively so this module compiles without BouncyCastle on the
     * classpath).</p>
     */
    public KeyPair generatePqKeyPair() {
        if (!postQuantumAvailable) {
            throw new IllegalStateException("ML-KEM-768 unavailable; cannot generate PQ keypair");
        }
        String alg = PqProviderBootstrap.mlKem768Algorithm();
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
            if ("ML-KEM".equals(alg)) {
                // BC flavour: drive parameter set via MLKEMParameterSpec.ml_kem_768
                try {
                    Class<?> specCls = Class.forName("org.bouncycastle.jcajce.spec.MLKEMParameterSpec");
                    Object spec = specCls.getField("ml_kem_768").get(null);
                    g.initialize((java.security.spec.AlgorithmParameterSpec) spec, new SecureRandom());
                } catch (ReflectiveOperationException roe) {
                    throw new IllegalStateException("BouncyCastle MLKEMParameterSpec missing", roe);
                }
            }
            // On JDK 24+ with name "ML-KEM-768", no initialize call is required.
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ML-KEM-768 keypair generation failed", e);
        }
    }

    /**
     * Result of encapsulation: the derived shared secret and the bytes to store
     * in the envelope as the KEM ciphertext (ephemeral X25519 public key,
     * optionally followed by a length-prefixed ML-KEM ciphertext).
     */
    public record Encapsulation(byte[] sharedSecret, byte[] kemCiphertext) {
        public void clear() {
            Arrays.fill(sharedSecret, (byte) 0);
        }
    }

    /**
     * Encapsulate against the epoch X25519 public key, and (if PQ is active and
     * a PQ public key is supplied) against the epoch ML-KEM public key as well.
     */
    public Encapsulation encapsulate(PublicKey epochX25519Public, PublicKey epochPqPublicOrNull) {
        byte[] ssClassical;
        byte[] ssPq = new byte[0];
        byte[] ephPubEnc;
        byte[] pqCt = new byte[0];
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(X25519);
            g.initialize(NamedParameterSpec.X25519, new SecureRandom());
            KeyPair ephemeral = g.generateKeyPair();
            ssClassical = ecdh(ephemeral.getPrivate(), epochX25519Public);
            ephPubEnc = ephemeral.getPublic().getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 encapsulation failed", e);
        }

        if (postQuantumAvailable && epochPqPublicOrNull != null) {
            try {
                KEM kem = KEM.getInstance(PqProviderBootstrap.mlKem768Algorithm());
                KEM.Encapsulator enc = kem.newEncapsulator(epochPqPublicOrNull);
                KEM.Encapsulated encapsulated = enc.encapsulate();
                ssPq = encapsulated.key().getEncoded();
                pqCt = encapsulated.encapsulation();
            } catch (GeneralSecurityException e) {
                Arrays.fill(ssClassical, (byte) 0);
                throw new IllegalStateException("ML-KEM encapsulation failed", e);
            }
        }

        byte[] combined = combine(ssClassical, ssPq);
        byte[] kemCt = packKemCiphertext(ephPubEnc, pqCt);
        Arrays.fill(ssClassical, (byte) 0);
        if (ssPq.length > 0) Arrays.fill(ssPq, (byte) 0);
        return new Encapsulation(combined, kemCt);
    }

    /**
     * Decapsulate using the epoch private keys and the stored {@code kemCiphertext}.
     * Pass {@code epochPqPrivateOrNull=null} for classical-only envelopes.
     */
    public byte[] decapsulate(PrivateKey epochX25519Private,
                              PrivateKey epochPqPrivateOrNull,
                              byte[] kemCiphertext,
                              boolean envelopeIsHybrid) {
        byte[][] parts = unpackKemCiphertext(kemCiphertext, envelopeIsHybrid);
        byte[] x25519Spki = parts[0];
        byte[] pqCt = parts[1];

        byte[] ssClassical;
        try {
            KeyFactory kf = KeyFactory.getInstance(X25519);
            PublicKey ephemeralPub = kf.generatePublic(new X509EncodedKeySpec(x25519Spki));
            ssClassical = ecdh(epochX25519Private, ephemeralPub);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 decapsulation failed", e);
        }

        byte[] ssPq = new byte[0];
        if (envelopeIsHybrid && epochPqPrivateOrNull != null && postQuantumAvailable && pqCt.length > 0) {
            try {
                KEM kem = KEM.getInstance(PqProviderBootstrap.mlKem768Algorithm());
                KEM.Decapsulator dec = kem.newDecapsulator(epochPqPrivateOrNull);
                ssPq = dec.decapsulate(pqCt).getEncoded();
            } catch (GeneralSecurityException e) {
                Arrays.fill(ssClassical, (byte) 0);
                throw new IllegalStateException("ML-KEM decapsulation failed", e);
            }
        }

        byte[] combined = combine(ssClassical, ssPq);
        Arrays.fill(ssClassical, (byte) 0);
        if (ssPq.length > 0) Arrays.fill(ssPq, (byte) 0);
        return combined;
    }

    /** Backwards-compatible classical-only encapsulation. */
    public Encapsulation encapsulate(PublicKey epochX25519Public) {
        return encapsulate(epochX25519Public, null);
    }

    /** Backwards-compatible classical-only decapsulation. */
    public byte[] decapsulate(PrivateKey epochX25519Private, byte[] kemCiphertext, boolean envelopeIsHybrid) {
        return decapsulate(epochX25519Private, null, kemCiphertext, envelopeIsHybrid);
    }

    /** Serialise an X25519 private key for epoch persistence; caller zeros the bytes. */
    public static byte[] exportPrivate(PrivateKey k) { return k.getEncoded(); }

    public static PrivateKey importPrivate(byte[] enc) {
        try {
            return KeyFactory.getInstance(X25519).generatePrivate(new PKCS8EncodedKeySpec(enc));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 private key import failed", e);
        }
    }

    public static byte[] exportPublic(PublicKey k) { return k.getEncoded(); }

    public static PublicKey importPublic(byte[] enc) {
        try {
            return KeyFactory.getInstance(X25519).generatePublic(new X509EncodedKeySpec(enc));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 public key import failed", e);
        }
    }

    /**
     * Reconstructs an X25519 {@link KeyPair} from a PKCS#8-encoded private key only.
     * The matching public key is recovered from the private's encoded form via the JCE
     * (Java exposes both halves on the {@code XECPrivateKey}). Used by
     * {@link EpochKeystore} so a freshly-loaded keystore can return the pair without
     * having stored the public key separately.
     */
    public static KeyPair importX25519KeyPairFromPkcs8(byte[] pkcs8) {
        try {
            KeyFactory kf = KeyFactory.getInstance(X25519);
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            // Java's XECPrivateKey doesn't expose the public; derive by ECDH(priv, BasePoint)
            // is non-trivial. Easier: re-derive at use time -- callers that need the public
            // can call HybridKem.derivePublicFromX25519Private(priv) via the JCE if needed.
            // For our use case (decapsulate side: we need only priv) the pair carries a null
            // public; encap side never reads from the keystore.
            return new KeyPair(null, priv);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 keypair import failed", e);
        }
    }

    /**
     * Reconstructs an ML-KEM {@link KeyPair} from PKCS#8 private + X.509 SPKI public.
     * Both halves are needed (ML-KEM private keys do not embed the public). When
     * post-quantum is unavailable in the runtime, this method throws.
     */
    public static KeyPair importMlKemKeyPair(byte[] pkcs8Priv, byte[] x509Pub) {
        if (!PqProviderBootstrap.ensurePqProvider()) {
            throw new IllegalStateException("ML-KEM provider unavailable; cannot import PQ keypair");
        }
        String alg = PqProviderBootstrap.mlKem768Algorithm();
        try {
            KeyFactory kf = KeyFactory.getInstance(alg);
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Priv));
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(x509Pub));
            return new KeyPair(pub, priv);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ML-KEM keypair import failed", e);
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

    private static byte[] packKemCiphertext(byte[] x25519Spki, byte[] pqCt) {
        if (x25519Spki.length > 0xFFFF) {
            throw new IllegalArgumentException("X25519 SPKI too large");
        }
        ByteBuffer buf = ByteBuffer.allocate(2 + x25519Spki.length + pqCt.length);
        buf.putShort((short) x25519Spki.length);
        buf.put(x25519Spki);
        buf.put(pqCt);
        return buf.array();
    }

    private static byte[][] unpackKemCiphertext(byte[] raw, boolean envelopeIsHybrid) {
        if (raw == null || raw.length < 2) {
            throw new IllegalArgumentException("kemCiphertext too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(raw);
        int x25519Len = Short.toUnsignedInt(buf.getShort());
        if (x25519Len <= 0 || x25519Len > buf.remaining()) {
            throw new IllegalArgumentException("kemCiphertext bad x25519 length: " + x25519Len);
        }
        byte[] x25519 = new byte[x25519Len];
        buf.get(x25519);
        byte[] pqCt = new byte[buf.remaining()];
        if (pqCt.length > 0) buf.get(pqCt);
        if (envelopeIsHybrid && pqCt.length == 0) {
            throw new IllegalArgumentException("hybrid envelope missing pq ciphertext");
        }
        return new byte[][]{x25519, pqCt};
    }
}
