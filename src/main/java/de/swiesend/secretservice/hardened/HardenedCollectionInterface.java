package de.swiesend.secretservice.hardened;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * Public surface of the hardened decorator. Mirrors the subset of
 * {@code CollectionInterface} that is safe to expose with application-layer encryption:
 * only callback-based plaintext access; no {@code getSecret(String)} returning raw {@code char[]}.
 *
 * <p>See the design plan for the threat model. In particular, {@link HardenedStatus#resistsSameUidAttacker()}
 * tells you whether the configured {@link KeyMaterialProvider} actually defends against
 * a malicious same-UID process (CVE-2018-19358); most do not.</p>
 */
public interface HardenedCollectionInterface extends AutoCloseable {

    Optional<String> createItem(String label, CharSequence secret);

    Optional<String> createItem(String label, CharSequence secret, Map<String, String> attributes);

    /**
     * Access the plaintext of a hardened item inside a callback; the {@code char[]} is
     * zeroed after the callback returns or throws.
     *
     * <p>Returns {@link Optional#empty()} if the item does not exist, is not a hardened item
     * (missing magic / {@code hardened.version}), or the callback returned null.</p>
     */
    <R> Optional<R> withSecret(String objectPath, Function<char[], R> callback);

    /** Access all hardened items' plaintexts under a single callback; all arrays zeroed on exit. */
    <R> Optional<R> withSecrets(Function<Map<String, char[]>, R> callback);

    boolean deleteItem(String objectPath);

    /** Rotate the collection epoch: rewrap every hardened item under a fresh epoch id. */
    boolean rotateEpoch();

    /** Current runtime status: epoch, time binding, threat coverage, algorithms. */
    HardenedStatus status();

    @Override
    void close();
}
