package de.swiesend.secretservice.hardened;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * AEAD dispatch keyed by the envelope's {@code aead_id}. Every supported suite uses a 32-byte key,
 * a 12-byte nonce, and a 16-byte tag, so only the cipher/key-spec differ; the per-item DEK and the
 * envelope layout are identical across suites. All ciphers are JDK-native (no third-party provider).
 */
final class Aead {

    private Aead() {}

    /** Shared key length for every supported AEAD. */
    static final int KEY_LEN = 32;
    private static final int TAG_BITS = 128;

    static boolean isSupported(byte id) {
        return id == Envelope.AEAD_ID_AES256_GCM || id == Envelope.AEAD_ID_CHACHA20_POLY1305;
    }

    static byte[] encrypt(byte id, byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
            throws GeneralSecurityException {
        return doCipher(Cipher.ENCRYPT_MODE, id, key, nonce, plaintext, aad);
    }

    static byte[] decrypt(byte id, byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
            throws GeneralSecurityException {
        return doCipher(Cipher.DECRYPT_MODE, id, key, nonce, ciphertext, aad);
    }

    private static byte[] doCipher(int mode, byte id, byte[] key, byte[] nonce, byte[] input, byte[] aad)
            throws GeneralSecurityException {
        Cipher c;
        SecretKeySpec ks;
        AlgorithmParameterSpec ps;
        switch (id) {
            case Envelope.AEAD_ID_AES256_GCM -> {
                c = Cipher.getInstance("AES/GCM/NoPadding");
                ks = new SecretKeySpec(key, "AES");
                ps = new GCMParameterSpec(TAG_BITS, nonce);
            }
            case Envelope.AEAD_ID_CHACHA20_POLY1305 -> {
                c = Cipher.getInstance("ChaCha20-Poly1305");
                ks = new SecretKeySpec(key, "ChaCha20");
                ps = new IvParameterSpec(nonce);
            }
            default -> throw new GeneralSecurityException(
                    "unsupported aead_id: 0x" + Integer.toHexString(id & 0xff));
        }
        c.init(mode, ks, ps);
        c.updateAAD(aad);
        return c.doFinal(input);
    }

    static String label(byte id) {
        return switch (id) {
            case Envelope.AEAD_ID_AES256_GCM -> "aes-256-gcm";
            case Envelope.AEAD_ID_CHACHA20_POLY1305 -> "chacha20-poly1305";
            default -> "aead-id-0x" + Integer.toHexString(id & 0xff);
        };
    }
}
