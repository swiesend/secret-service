package de.swiesend.secretservice.hardened;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies the {@link Aead} suite dispatch: each id round-trips, matches a direct JDK
 * {@link Cipher} computation over the same key/nonce/AAD (proving the key-spec, parameter-spec, and
 * AAD wiring are correct), authenticates the AAD, and rejects unknown ids.
 */
class AeadTest {

    private static byte[] key() {
        byte[] k = new byte[Aead.KEY_LEN];
        for (int i = 0; i < k.length; i++) k[i] = (byte) (i + 1);
        return k;
    }

    private static final byte[] NONCE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    private static final byte[] AAD = "header-as-associated-data".getBytes();
    private static final byte[] PLAIN = "attack at dawn, bring coffee".getBytes();

    @Test
    void aesGcmMatchesDirectJdkCipherAndRoundTrips() throws Exception {
        byte[] ct = Aead.encrypt(Envelope.AEAD_ID_AES256_GCM, key(), NONCE, PLAIN, AAD);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(), "AES"), new GCMParameterSpec(128, NONCE));
        c.updateAAD(AAD);
        assertArrayEquals(c.doFinal(PLAIN), ct, "Aead AES-GCM must match a direct JDK GCM computation");

        assertArrayEquals(PLAIN, Aead.decrypt(Envelope.AEAD_ID_AES256_GCM, key(), NONCE, ct, AAD));
    }

    @Test
    void chaCha20Poly1305MatchesDirectJdkCipherAndRoundTrips() throws Exception {
        byte[] ct = Aead.encrypt(Envelope.AEAD_ID_CHACHA20_POLY1305, key(), NONCE, PLAIN, AAD);

        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(), "ChaCha20"), new IvParameterSpec(NONCE));
        c.updateAAD(AAD);
        assertArrayEquals(c.doFinal(PLAIN), ct, "Aead ChaCha20-Poly1305 must match a direct JDK computation");

        assertArrayEquals(PLAIN, Aead.decrypt(Envelope.AEAD_ID_CHACHA20_POLY1305, key(), NONCE, ct, AAD));
    }

    @Test
    void tagIs16BytesAndSuitesDiffer() throws Exception {
        byte[] gcm = Aead.encrypt(Envelope.AEAD_ID_AES256_GCM, key(), NONCE, PLAIN, AAD);
        byte[] cha = Aead.encrypt(Envelope.AEAD_ID_CHACHA20_POLY1305, key(), NONCE, PLAIN, AAD);
        // both append a 16-byte Poly1305/GCM tag
        assertFalse(Arrays.equals(gcm, cha), "different AEAD suites must produce different ciphertext");
        assert gcm.length == PLAIN.length + 16;
        assert cha.length == PLAIN.length + 16;
    }

    @Test
    void tamperedAssociatedDataFailsAuthentication() throws Exception {
        byte[] ct = Aead.encrypt(Envelope.AEAD_ID_AES256_GCM, key(), NONCE, PLAIN, AAD);
        byte[] badAad = AAD.clone();
        badAad[0] ^= 0x01;
        assertThrows(AEADBadTagException.class,
                () -> Aead.decrypt(Envelope.AEAD_ID_AES256_GCM, key(), NONCE, ct, badAad));
    }

    @Test
    void unknownAeadIdIsRejected() {
        assertThrows(GeneralSecurityException.class,
                () -> Aead.encrypt((byte) 0x7f, key(), NONCE, PLAIN, AAD));
        assertFalse(Aead.isSupported((byte) 0x7f));
    }
}
