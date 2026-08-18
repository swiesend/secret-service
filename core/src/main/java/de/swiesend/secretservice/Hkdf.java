package de.swiesend.secretservice;

import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;
import java.security.GeneralSecurityException;

/**
 * HKDF-SHA256 (RFC 5869) extract-then-expand over the JDK's native Key Derivation Function API
 * ({@code javax.crypto.KDF}, final since JDK 25 / JEP 510). Replaces the former third-party
 * {@code at.favre.lib:hkdf} dependency; the pseudo-random key stays inside the provider and is
 * never exposed to the caller.
 */
public final class Hkdf {

    private Hkdf() {}

    private static final String HKDF_SHA256 = "HKDF-SHA256";
    /** RFC 5869: an absent salt is a string of HashLen (32 for SHA-256) zero bytes. */
    private static final int HASH_LEN = 32;

    /**
     * Performs {@code HKDF-Expand(HKDF-Extract(salt, ikm), info, length)} with SHA-256.
     *
     * @param salt   the extract salt; {@code null} means the RFC 5869 "absent salt" (HashLen zeros)
     * @param ikm    the input keying material (secret)
     * @param info   the expand context; {@code null} is treated as empty
     * @param length the number of output bytes
     * @return the derived key material
     */
    public static byte[] extractThenExpandSha256(byte[] salt, byte[] ikm, byte[] info, int length) {
        byte[] s = (salt == null) ? new byte[HASH_LEN] : salt;
        byte[] i = (info == null) ? new byte[0] : info;
        try {
            KDF kdf = KDF.getInstance(HKDF_SHA256);
            return kdf.deriveData(HKDFParameterSpec.ofExtract().addSalt(s).addIKM(ikm).thenExpand(i, length));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF-SHA256 derivation failed", e);
        }
    }
}
