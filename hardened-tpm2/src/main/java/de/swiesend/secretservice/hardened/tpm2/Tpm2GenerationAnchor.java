package de.swiesend.secretservice.hardened.tpm2;

import de.swiesend.secretservice.hardened.GenerationAnchor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tss.Tpm;
import tss.TpmFactory;
import tss.tpm.TPM_HANDLE;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * {@link GenerationAnchor} backed by a TPM 2.0 NV <b>monotonic counter</b>.
 *
 * <p>The NV counter is the rollback-resistant primitive the anchor needs: it can be incremented
 * but never decremented or set, not even by the TPM owner, and it survives reboots. The
 * {@link de.swiesend.secretservice.hardened.EpochKeystore} treats {@link #read()} as a floor and
 * refuses any keystore snapshot below it, so an attacker who re-introduces an older keystore item
 * is detected instead of silently resurrecting destroyed epoch keys.</p>
 *
 * <p>The counter's NV index must be provisioned once, out of band, with
 * {@link Tpm2Provisioner#defineGenerationCounter}. Increment is gated by the index auth value (the
 * password supplied here) so a hostile process cannot push the floor past the live keystore and
 * cause a fail-closed denial of service; the auth participates in the TPM's dictionary-attack
 * lockout. This instance holds one TPM connection open for its lifetime and closes it on
 * {@link #close()}. Note that {@code HardenedCollection.close()} does NOT close a
 * caller-supplied anchor unless the collection was built with {@code Builder.ownsAnchor(true)} --
 * otherwise close it yourself.</p>
 *
 * <h3>Threat coverage caveat</h3>
 * <p>Like {@link Tpm2KeyMaterialProvider}, this does not mediate a same-UID attacker who opens the
 * TPM device directly: with the password (read from the same place the legitimate process reads
 * it) they can increment the counter too. What the counter does provide is that <i>nobody</i> --
 * same-UID or not -- can move it backwards, so a keystore rollback cannot be made to look current.</p>
 */
public final class Tpm2GenerationAnchor implements GenerationAnchor {

    private static final Logger log = LoggerFactory.getLogger(Tpm2GenerationAnchor.class);

    /** Counter width: TPM NV counters are 8-byte big-endian. */
    private static final int COUNTER_BYTES = 8;

    private final Tpm tpm;
    private final TPM_HANDLE nvIndex;
    /** Raw NV index, kept for {@link #scopeKey()} so two distinct objects on one counter collide. */
    private final int nvIndexValue;
    private final byte[] auth;
    private boolean closed = false;

    /** Open against the platform TPM ({@code /dev/tpm*} / Windows TBS). */
    public static Tpm2GenerationAnchor forPlatformTpm(int nvIndex, char[] password) {
        return new Tpm2GenerationAnchor(nvIndex, password, TpmFactory::platformTpm);
    }

    /** Open against a TPM simulator on {@code localhost:2321} (tests / CI). */
    public static Tpm2GenerationAnchor forSimulator(int nvIndex, char[] password) {
        return new Tpm2GenerationAnchor(nvIndex, password, TpmFactory::localTpmSimulator);
    }

    /**
     * @param nvIndex     NV index handle value the counter was provisioned at (see
     *                    {@link Tpm2Provisioner#defineGenerationCounter}).
     * @param password    index auth value; a defensive copy is taken and the caller may zero theirs.
     * @param tpmSupplier returns a connected {@link Tpm} that this instance owns and closes.
     * @throws IllegalStateException if the counter index is not defined or the TPM is unreachable.
     */
    public Tpm2GenerationAnchor(int nvIndex, char[] password, Supplier<Tpm> tpmSupplier) {
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(tpmSupplier, "tpmSupplier");
        this.auth = charsToUtf8(password);
        Tpm opened;
        try {
            opened = tpmSupplier.get();
        } catch (RuntimeException e) {
            Arrays.fill(auth, (byte) 0);
            throw new IllegalStateException("TPM connection failed: " + e.getMessage(), e);
        }
        this.tpm = opened;
        // nvIndex is a full NV handle (e.g. 0x01800200), so construct the handle directly.
        // TPM_HANDLE.NV(x) computes 0x01000000 + x and expects a 24-bit offset; feeding it a
        // full handle double-applies the NV base (0x01800200 -> 0x02800200), yielding an
        // HMAC-session handle type that the TPM rejects with TPM_RC_VALUE.
        this.nvIndex = new TPM_HANDLE(nvIndex);
        this.nvIndexValue = nvIndex;
        this.nvIndex.AuthValue = this.auth;
        try {
            // Fail fast (and clearly) if the counter was never provisioned.
            tpm.NV_ReadPublic(this.nvIndex);
        } catch (RuntimeException e) {
            closeQuietly();
            throw new IllegalStateException("TPM NV counter at index 0x" + Integer.toHexString(nvIndex)
                    + " is not defined; provision it with Tpm2Provisioner.defineGenerationCounter", e);
        }
    }

    @Override
    public synchronized long read() {
        ensureOpen();
        try {
            return toLong(tpm.NV_Read(nvIndex, nvIndex, COUNTER_BYTES, 0));
        } catch (RuntimeException e) {
            throw new IllegalStateException("TPM NV counter read failed: " + e.getMessage(), e);
        }
    }

    /**
     * Largest gap {@link #advanceTo(long)} will close. A TPM NV counter has no "set" operation, so
     * the only way up is one {@code NV_Increment} at a time -- each a write to the TPM's limited
     * NV flash, at roughly 5-20ms. Normal operation advances by one per persist, so a large gap
     * never comes from normal operation: it means the keystore was restored from a backup taken on
     * a different machine, or points at the wrong NV index, or is corrupt. Grinding through it would
     * spend hours in what the caller invoked as a load, and burn NV write cycles doing it.
     */
    static final long MAX_ADVANCE = 4096;

    /**
     * {@inheritDoc}
     *
     * @throws IllegalStateException if {@code target} exceeds the counter by more than
     *         {@value #MAX_ADVANCE}, or if the counter stops advancing before reaching it
     */
    @Override
    public synchronized long advanceTo(long target) {
        ensureOpen();
        try {
            long current = toLong(tpm.NV_Read(nvIndex, nvIndex, COUNTER_BYTES, 0));
            if (target - current > MAX_ADVANCE) {
                throw new IllegalStateException(
                        "Refusing to advance the TPM NV counter at index 0x"
                                + Integer.toHexString(nvIndexValue) + " by " + (target - current)
                                + " steps (limit " + MAX_ADVANCE + "). A counter has no set operation, so"
                                + " this would take one NV write per step -- hours of TPM writes, and NV"
                                + " flash wear. A gap this large means the keystore does not belong to"
                                + " this counter: typically a keystore restored from another machine, or"
                                + " an anchor pointed at the wrong NV index. Verify the index, or"
                                + " provision a fresh counter for this collection.");
            }
            while (current < target) {
                tpm.NV_Increment(nvIndex, nvIndex);
                long next = toLong(tpm.NV_Read(nvIndex, nvIndex, COUNTER_BYTES, 0));
                // A counter that does not move would spin here forever, holding this object's
                // monitor. Treat "incremented but unchanged" as a hardware/emulation fault.
                if (next <= current) {
                    throw new IllegalStateException(
                            "TPM NV counter at index 0x" + Integer.toHexString(nvIndexValue)
                                    + " did not advance past " + current + " after NV_Increment;"
                                    + " refusing to loop.");
                }
                current = next;
            }
            return current;
        } catch (IllegalStateException e) {
            throw e; // already diagnostic; do not re-wrap
        } catch (RuntimeException e) {
            throw new IllegalStateException("TPM NV counter advance failed: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            Arrays.fill(auth, (byte) 0);
            closeQuietly();
            closed = true;
        }
    }

    private void ensureOpen() {
        if (closed) throw new IllegalStateException("Tpm2GenerationAnchor is closed");
    }

    /**
     * The NV index this counter lives at, so two distinct anchor objects provisioned on the SAME
     * counter are detected as sharing a collection -- not just the same object injected twice.
     */
    @Override
    public Object scopeKey() { return "tpm2-nv:" + Integer.toHexString(nvIndexValue); }

    private void closeQuietly() {
        try {
            tpm.close();
        } catch (IOException e) {
            log.debug("tpm.close() failed: {}", e.toString());
        }
    }

    private static long toLong(byte[] be8) {
        if (be8 == null || be8.length != COUNTER_BYTES) {
            throw new IllegalStateException("TPM NV counter returned " + (be8 == null ? "null" : be8.length)
                    + " bytes; expected " + COUNTER_BYTES);
        }
        return ByteBuffer.wrap(be8).order(ByteOrder.BIG_ENDIAN).getLong();
    }

    private static byte[] charsToUtf8(char[] chars) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] out = new byte[encoded.remaining()];
        encoded.get(out);
        if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
        return out;
    }
}
