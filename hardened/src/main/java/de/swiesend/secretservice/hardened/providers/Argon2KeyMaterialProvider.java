package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Wrapper {@link KeyMaterialProvider} that runs Argon2id over the underlying provider's
 * pepper before handing it to the hardened layer. Defends class-C (offline brute-force)
 * against attackers who exfiltrate a sealed/encrypted artefact and try every plausible
 * pepper -- the per-attempt cost rises from "a few HKDF hashes" to "tens of milliseconds
 * + tens of MB of memory".
 *
 * <h3>What this provider does NOT do</h3>
 * <ul>
 *   <li><b>Class A (same-UID live process)</b>: unchanged. Argon2 doesn't help against an
 *       attacker who can ptrace the JVM and read the post-Argon pepper directly.</li>
 *   <li><b>Class B (cross-UID)</b>: unchanged from the underlying provider; Argon2 doesn't
 *       affect file-mode or D-Bus permissions.</li>
 *   <li><b>Class D (network HNDL)</b>: unchanged; orthogonal to PQ KEM.</li>
 * </ul>
 * It bumps the underlying provider's class-C rating one notch (or affirms it at REAL when
 * already there) and otherwise passes the rating through verbatim.
 *
 * <h3>Caching</h3>
 * <p>Argon2 is intentionally slow (default ~64 MB / 3 iterations / 4-way parallelism),
 * so this provider runs it <b>once</b> at first {@link #getPepper()} call and caches the
 * result for the JVM lifetime. The cache is a {@code byte[]} (base64 ASCII so it round-trips
 * losslessly through UTF-8); subsequent {@code getPepper()} returns a fresh char[] clone of
 * it. {@link #close()} zeros the cache; it closes the inner provider only when constructed with
 * {@code ownsInner = true} -- by default the caller owns (and closes) what it constructed.</p>
 *
 * <h3>Salt</h3>
 * <p>Argon2 needs a salt. We use a caller-supplied byte[] (typically a fixed deployment
 * identifier such as the application name + install id). The salt is intentionally NOT
 * derived from the pepper -- that would be circular and remove the cost separation. A
 * fixed deployment-wide salt is fine for class-C defense (the attacker has to do Argon2
 * per pepper guess, not per item).</p>
 *
 * <h3>Dependency: BouncyCastle (reflective)</h3>
 * <p>This provider uses BouncyCastle's {@code Argon2BytesGenerator} reflectively so the
 * hardened module class-loads without {@code bcprov-jdk18on} on the classpath. Consumers
 * who use this provider must add bcprov-jdk18on 1.78+ to their runtime classpath
 * (same opt-in pattern as {@code PqProviderBootstrap}). The constructor probes for
 * BouncyCastle availability and fails closed with a clear diagnostic when absent.</p>
 *
 * <h3>Sample usage</h3>
 * <pre>
 * KeyMaterialProvider stretched = new Argon2KeyMaterialProvider(
 *         new EnvVarKeyMaterialProvider(),               // weak inner pepper
 *         "myapp-prod-install-2026".getBytes(US_ASCII),  // deployment-wide salt
 *         Argon2KeyMaterialProvider.Profile.INTERACTIVE);  // ~64 MB, ~150 ms
 * HardenedCollection coll = HardenedCollection.builder(base, stretched).build();
 * </pre>
 */
public final class Argon2KeyMaterialProvider implements KeyMaterialProvider {

    private static final Logger log = LoggerFactory.getLogger(Argon2KeyMaterialProvider.class);

    /** Default Argon2 profiles drawn from RFC 9106 §4 recommendations. */
    public enum Profile {
        /** ~64 MB / 3 iters / 4 lanes / 32-byte output -- default; ~150 ms on modern hardware. */
        INTERACTIVE(65536, 3, 4, 32),
        /** ~256 MB / 4 iters / 4 lanes / 32-byte output -- ~600 ms; for offline-only adversaries. */
        SENSITIVE(262144, 4, 4, 32),
        /** ~16 MB / 3 iters / 1 lane / 32-byte output -- low-spec / embedded; ~30 ms. */
        EMBEDDED(16384, 3, 1, 32);

        final int memoryKiB;
        final int iterations;
        final int parallelism;
        final int outputLen;

        Profile(int memoryKiB, int iterations, int parallelism, int outputLen) {
            this.memoryKiB = memoryKiB;
            this.iterations = iterations;
            this.parallelism = parallelism;
            this.outputLen = outputLen;
        }
    }

    private static final String BC_GENERATOR = "org.bouncycastle.crypto.generators.Argon2BytesGenerator";
    private static final String BC_PARAMS    = "org.bouncycastle.crypto.params.Argon2Parameters";
    private static final String BC_BUILDER   = "org.bouncycastle.crypto.params.Argon2Parameters$Builder";

    private final KeyMaterialProvider inner;
    private final boolean ownsInner;
    private final byte[] salt;
    private final Profile profile;
    private final char[] cachedStretchedPepper;
    private volatile boolean closed = false;

    /**
     * Non-owning: {@code close()} does <b>not</b> close {@code inner}, per the library-wide
     * "you close what you constructed" policy -- the caller constructed the inner provider and may
     * be sharing it with other collections. Use the four-argument constructor with
     * {@code ownsInner = true} for close-through.
     */
    public Argon2KeyMaterialProvider(KeyMaterialProvider inner, byte[] salt, Profile profile) {
        this(inner, salt, profile, false);
    }

    /**
     * @param ownsInner when true, {@code close()} also closes {@code inner} (exactly once). Leave
     *                  false when the inner provider is shared -- closing it here would zero its
     *                  cached pepper underneath every other holder.
     */
    public Argon2KeyMaterialProvider(KeyMaterialProvider inner, byte[] salt, Profile profile,
                                     boolean ownsInner) {
        Objects.requireNonNull(inner, "inner provider");
        Objects.requireNonNull(salt, "salt");
        Objects.requireNonNull(profile, "profile");
        if (salt.length < 8) {
            throw new IllegalArgumentException("Argon2 salt must be at least 8 bytes");
        }
        ensureBouncyCastleAvailable();
        this.inner = inner;
        this.ownsInner = ownsInner;
        this.salt = salt.clone();
        this.profile = profile;
        // Stretch once at construction time so failures surface immediately, not on first use.
        this.cachedStretchedPepper = stretchOnce();
    }

    private static void ensureBouncyCastleAvailable() {
        try {
            Class.forName(BC_GENERATOR, false, Argon2KeyMaterialProvider.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                    "Argon2KeyMaterialProvider requires BouncyCastle on the runtime classpath. "
                            + "Add 'org.bouncycastle:bcprov-jdk18on:1.78+' to your runtime dependencies.", e);
        }
    }

    private char[] stretchOnce() {
        char[] innerPepper = inner.getPepper();
        byte[] innerBytes = charsToUtf8(innerPepper);
        byte[] derived = new byte[profile.outputLen];
        try {
            // Reflective: build Argon2Parameters and run the generator.
            Class<?> paramsCls = Class.forName(BC_PARAMS);
            Class<?> builderCls = Class.forName(BC_BUILDER);
            int argon2idType = paramsCls.getField("ARGON2_id").getInt(null);
            Constructor<?> builderCtor = builderCls.getConstructor(int.class);
            Object builder = builderCtor.newInstance(argon2idType);
            // Builder fluent setters. Each returns Builder for chaining.
            builder = builderCls.getMethod("withVersion", int.class)
                    .invoke(builder, paramsCls.getField("ARGON2_VERSION_13").getInt(null));
            builder = builderCls.getMethod("withMemoryAsKB", int.class)
                    .invoke(builder, profile.memoryKiB);
            builder = builderCls.getMethod("withIterations", int.class)
                    .invoke(builder, profile.iterations);
            builder = builderCls.getMethod("withParallelism", int.class)
                    .invoke(builder, profile.parallelism);
            builder = builderCls.getMethod("withSalt", byte[].class)
                    .invoke(builder, (Object) salt);
            Object params = builderCls.getMethod("build").invoke(builder);

            Class<?> genCls = Class.forName(BC_GENERATOR);
            Object gen = genCls.getDeclaredConstructor().newInstance();
            genCls.getMethod("init", paramsCls).invoke(gen, params);
            Method generate = genCls.getMethod("generateBytes", byte[].class, byte[].class);
            generate.invoke(gen, innerBytes, derived);

            // Encode as base64 ASCII so the result is valid UTF-8 (round-trip safe through
            // the existing HardenedCollection charsToUtf8 path).
            byte[] base64 = Base64.getEncoder().encode(derived);
            char[] stretched = new char[base64.length];
            for (int i = 0; i < base64.length; i++) stretched[i] = (char) (base64[i] & 0xff);
            Arrays.fill(base64, (byte) 0);
            log.info("Argon2KeyMaterialProvider: stretched pepper via Argon2id "
                            + "(memory={} KiB, iters={}, lanes={}, out={} B)",
                    profile.memoryKiB, profile.iterations, profile.parallelism, profile.outputLen);
            return stretched;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Argon2KeyMaterialProvider: BouncyCastle invocation failed", e);
        } finally {
            Arrays.fill(innerPepper, '\0');
            Arrays.fill(innerBytes, (byte) 0);
            Arrays.fill(derived, (byte) 0);
        }
    }

    @Override
    public char[] getPepper() {
        if (closed) throw new IllegalStateException("Argon2KeyMaterialProvider is closed");
        char[] out = cachedStretchedPepper.clone();
        // Re-check after the copy; see EnvVarKeyMaterialProvider.getPepper for why an all-zero
        // pepper must never be returned in place of throwing.
        if (closed) {
            Arrays.fill(out, '\0');
            throw new IllegalStateException("Argon2KeyMaterialProvider is closed");
        }
        return out;
    }

    @Override
    public ThreatCoverage threatCoverage() {
        ThreatCoverage tc = inner.threatCoverage();
        // Argon2 only changes class-C; bump from NONE -> PARTIAL or affirm REAL.
        ThreatCoverage.Level offline = switch (tc.offline()) {
            case NONE -> ThreatCoverage.Level.PARTIAL;
            case PARTIAL -> ThreatCoverage.Level.REAL;
            case REAL -> ThreatCoverage.Level.REAL;
            case NOT_APPLICABLE -> ThreatCoverage.Level.NOT_APPLICABLE;
        };
        return new ThreatCoverage(
                tc.sameUid(), tc.crossUid(), offline, tc.networkHndl(),
                "Argon2id-stretched (" + profile.name() + ", "
                        + profile.memoryKiB + " KiB / " + profile.iterations + " iters / "
                        + profile.parallelism + " lanes) over: " + tc.rationale());
    }

    @Override
    public void close() {
        // inner.close() sits INSIDE the guard and behind ownsInner: outside it, every repeat
        // close() closed the inner provider again, and closing it at all was wrong for a shared
        // inner -- another collection's getPepper() suddenly saw a zeroed cache. The wrapper closes
        // the inner provider only when the caller said it owns it, and then exactly once.
        if (!closed) {
            closed = true;   // before the zeroing, so a racing getPepper() throws rather than reads
            Arrays.fill(cachedStretchedPepper, '\0');
            Arrays.fill(salt, (byte) 0);
            if (ownsInner) {
                try {
                    inner.close();
                } catch (RuntimeException e) {
                    log.warn("Argon2KeyMaterialProvider: inner.close() threw: {}",
                            de.swiesend.secretservice.LogPolicy.cause(e));
                }
            }
        }
    }

    private static byte[] charsToUtf8(char[] chars) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] out = new byte[encoded.remaining()];
        encoded.get(out);
        if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
        return out;
    }
}
