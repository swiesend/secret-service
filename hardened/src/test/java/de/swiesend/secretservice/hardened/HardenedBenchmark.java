package de.swiesend.secretservice.hardened;

import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Lightweight throughput benchmark over the in-memory {@link FakeCollection}, so it measures the
 * per-item crypto cost (hybrid KEM + HKDF + AEAD) rather than D-Bus I/O. Disabled by default;
 * remove {@link Disabled} and run explicitly:
 *
 * <pre>mvn -pl hardened test -Dtest=HardenedBenchmark</pre>
 *
 * Use it to compare createItem/withSecret rates across AEAD suites and to sanity-check that
 * micro-optimizations (shared SecureRandom, buffer reuse) do not regress.
 */
@Disabled("manual benchmark; not part of the default suite")
class HardenedBenchmark {

    private static final int WARMUP = 500;
    private static final int ITERS = 5000;

    @Test
    void benchmarkBothAeadSuites() {
        for (AeadId aead : AeadId.values()) {
            benchmark(aead);
        }
    }

    private void benchmark(AeadId aead) {
        FakeCollection fake = new FakeCollection();
        KeyMaterialProvider provider = new EnvVarKeyMaterialProvider(
                "benchmark-pepper-of-a-reasonable-length-for-derivation");
        HardenedCollection h = HardenedCollection.builder(fake, provider)
                .acknowledgeSecurityTheater(true)
                .aead(aead)
                .build();

        String canary = null;
        for (int i = 0; i < WARMUP; i++) canary = h.createItem("w" + i, "secret-value").orElseThrow();
        for (int i = 0; i < WARMUP; i++) h.withSecret(canary, s -> s.length);

        long t0 = System.nanoTime();
        String last = null;
        for (int i = 0; i < ITERS; i++) last = h.createItem("k" + i, "secret-value-" + i).orElseThrow();
        long writeNs = System.nanoTime() - t0;

        t0 = System.nanoTime();
        for (int i = 0; i < ITERS; i++) h.withSecret(last, s -> s.length);
        long readNs = System.nanoTime() - t0;

        System.out.printf("%-20s  createItem: %,d ops/s   withSecret: %,d ops/s%n",
                aead, ITERS * 1_000_000_000L / writeNs, ITERS * 1_000_000_000L / readNs);
    }
}
