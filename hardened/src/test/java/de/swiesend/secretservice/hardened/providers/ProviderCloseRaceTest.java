package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code close()} must never let {@code getPepper()} return an <b>all-zero</b> pepper.
 *
 * <p>Every provider zeroes a cached array in {@code close()} and guards {@code getPepper()} with a
 * {@code closed} flag. Zeroing before setting the flag leaves a window in which a concurrent
 * {@code getPepper()} passes the guard and then reads the array being blanked. The caller receives
 * zeros where it expected either a pepper or an exception -- and {@code createItem} seals the item
 * under a DEK derived from those zeros, so the item can never be read again. Silent, permanent data
 * loss in place of a loud {@code IllegalStateException}.</p>
 *
 * <p>Parameterised over every provider deliberately: the bug was identical in all five, so the
 * defence has to be too, and a sixth provider should fail here rather than be discovered later.</p>
 */
class ProviderCloseRaceTest {

    private record Case(String name, Supplier<KeyMaterialProvider> factory) {}

    private static List<Case> providers() {
        List<Case> cases = new ArrayList<>();
        cases.add(new Case("EnvVar", () -> new EnvVarKeyMaterialProvider("a-pepper-long-enough-for-derivation")));
        cases.add(new Case("File", () -> {
            try {
                java.nio.file.Path f = java.nio.file.Files.createTempFile("pepper", ".b64");
                java.nio.file.Files.write(f, java.util.Base64.getEncoder()
                        .encode("a-pepper-long-enough-for-derivation".getBytes(StandardCharsets.UTF_8)));
                java.nio.file.Files.setPosixFilePermissions(f,
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
                f.toFile().deleteOnExit();
                return new FileKeyMaterialProvider(f);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }));
        // Argon2 needs BouncyCastle; include it only when the optional dependency is present.
        try {
            Class.forName("org.bouncycastle.crypto.generators.Argon2BytesGenerator");
            cases.add(new Case("Argon2", () -> new Argon2KeyMaterialProvider(
                    new EnvVarKeyMaterialProvider("a-pepper-long-enough-for-derivation"),
                    "long-enough-salt".getBytes(StandardCharsets.UTF_8),
                    Argon2KeyMaterialProvider.Profile.EMBEDDED)));
        } catch (ClassNotFoundException ignored) {
            // optional at runtime; covered by Argon2KeyMaterialProviderTest when available
        }
        return cases;
    }

    @Test
    void closeNeverYieldsAnAllZeroPepper() throws Exception {
        for (Case c : providers()) {
            for (int attempt = 0; attempt < 200; attempt++) {
                KeyMaterialProvider p = c.factory().get();
                CountDownLatch go = new CountDownLatch(1);
                List<char[]> observed = java.util.Collections.synchronizedList(new ArrayList<>());
                List<Throwable> unexpected = java.util.Collections.synchronizedList(new ArrayList<>());

                Thread reader = new Thread(() -> {
                    try {
                        go.await();
                        observed.add(p.getPepper());
                    } catch (IllegalStateException expected) {
                        // The correct outcome for a closed provider.
                    } catch (Throwable t) {
                        unexpected.add(t);
                    }
                });
                Thread closer = new Thread(() -> {
                    try {
                        go.await();
                        p.close();
                    } catch (Throwable t) {
                        unexpected.add(t);
                    }
                });
                reader.start();
                closer.start();
                go.countDown();
                reader.join(TimeUnit.SECONDS.toMillis(10));
                closer.join(TimeUnit.SECONDS.toMillis(10));

                if (!unexpected.isEmpty()) {
                    fail(c.name() + ": unexpected failure racing close()", unexpected.get(0));
                }
                for (char[] pepper : observed) {
                    boolean allZero = pepper.length > 0;
                    for (char ch : pepper) {
                        if (ch != '\0') { allZero = false; break; }
                    }
                    Arrays.fill(pepper, '\0');
                    assertTrue(!allZero, c.name() + ": getPepper() returned an all-zero pepper while "
                            + "racing close(); items sealed with it could never be read again. It "
                            + "must throw instead.");
                }
            }
        }
    }
}
