package de.swiesend.secretservice.hardened;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * RFC 6238 TOTP, HMAC-SHA-256 by default, 30-second step.
 * Used as a factor in DEK derivation; the generated 8-byte code joins the HKDF info string.
 */
public final class Totp {

    public static final long DEFAULT_STEP_SECONDS = 30L;
    public static final int DEFAULT_CODE_BYTES = 8;

    private Totp() {}

    public static long currentStep() {
        return currentStep(System.currentTimeMillis(), DEFAULT_STEP_SECONDS);
    }

    public static long currentStep(long millis, long stepSeconds) {
        if (stepSeconds <= 0) throw new IllegalArgumentException("stepSeconds must be positive");
        return (millis / 1000L) / stepSeconds;
    }

    /**
     * Computes a raw HOTP/TOTP code of {@code codeBytes} bytes for the given seed and step counter.
     * Uses HMAC-SHA-256. Not an RFC 4226 6-digit truncated code — we use the full HMAC bytes as
     * a KDF factor, since this is input to HKDF, not user-visible.
     */
    public static byte[] code(byte[] seed, long step, int codeBytes) {
        if (seed == null || seed.length == 0) throw new IllegalArgumentException("seed empty");
        if (codeBytes < 1 || codeBytes > 32) throw new IllegalArgumentException("codeBytes 1..32");
        byte[] counter = ByteBuffer.allocate(8).putLong(step).array();
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(seed, "HmacSHA256"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
        byte[] hmac = mac.doFinal(counter);
        try {
            return Arrays.copyOf(hmac, codeBytes);
        } finally {
            Arrays.fill(hmac, (byte) 0);
            Arrays.fill(counter, (byte) 0);
        }
    }

    public static byte[] code(byte[] seed, long step) {
        return code(seed, step, DEFAULT_CODE_BYTES);
    }
}
