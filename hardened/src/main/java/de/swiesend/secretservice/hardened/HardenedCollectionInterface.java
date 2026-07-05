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
 *
 * <h3>Choosing the right read method</h3>
 * <ul>
 *   <li><b>Comparing against a candidate value</b> (password check, token check):
 *       use {@link #matchesSecret(String, char[])}. The plaintext never leaves the
 *       library, the comparison is constant-time, and the candidate is zeroed on
 *       return. Strictly safer than comparing inside a {@code withSecret} callback.</li>
 *   <li><b>Deriving a non-sensitive value from the plaintext</b> (parse a JWT exp,
 *       derive an HMAC, check a format): use {@link #withSecret(String, Function)},
 *       reading its {@code @apiNote} first.</li>
 * </ul>
 */
public interface HardenedCollectionInterface extends AutoCloseable {

    Optional<String> createItem(String label, CharSequence secret);

    Optional<String> createItem(String label, CharSequence secret, Map<String, String> attributes);

    /**
     * Constant-time equality check against {@code candidate}. The plaintext is
     * decrypted, compared to {@code candidate}, then both are zeroed -- the caller
     * never sees the plaintext and does not need to write the comparison themselves.
     *
     * <p>Prefer this method whenever the use case is "does this match the thing the
     * user typed/supplied?". It removes two footguns at once:</p>
     * <ol>
     *   <li>The plaintext cannot leak to caller code (it is never handed out).</li>
     *   <li>The comparison runs in time proportional to {@code length}, not to the
     *       position of the first mismatch. A naive {@code Arrays.equals} inside a
     *       {@link #withSecret} callback short-circuits and leaks the first
     *       differing index through timing -- the classic password-compare oracle.</li>
     * </ol>
     *
     * @param objectPath D-Bus object path of the hardened item
     * @param candidate  caller-supplied plaintext candidate to compare against. <b>The
     *                   library zeros this array before returning</b> (whether the
     *                   match succeeded or not). Callers must not rely on the contents
     *                   of {@code candidate} after the call.
     * @return {@code Optional.of(true)} on match, {@code Optional.of(false)} on mismatch,
     *         {@code Optional.empty()} if the item does not exist, is not a hardened
     *         item, or could not be decrypted (wrong pepper / tampered).
     * @throws NullPointerException if {@code objectPath} or {@code candidate} is null
     */
    Optional<Boolean> matchesSecret(String objectPath, char[] candidate);

    /**
     * Access the plaintext of a hardened item inside a callback; the {@code char[]} is
     * zeroed after the callback returns or throws.
     *
     * <p>Returns {@link Optional#empty()} if the item does not exist, is not a hardened item
     * (missing magic / {@code hardened.version}), or the callback returned {@code null}.</p>
     *
     * @apiNote <b>Do NOT return the plaintext or anything derived from it.</b> Returning
     *          {@code new String(chars)}, the {@code char[]} itself, or a wrapper object
     *          that retains a reference defeats the zeroing guarantee: a {@code String} is
     *          immutable and cannot be cleared, and any external reference to the passed
     *          {@code char[]} keeps pointing at an array this method will fill with {@code 0}
     *          milliseconds later. The callback's body can also leak via side effects
     *          (logging, field capture) -- the library only guarantees the return path.
     *          For candidate-comparison use cases prefer {@link #matchesSecret}.
     */
    <R> Optional<R> withSecret(String objectPath, Function<char[], R> callback);

    /**
     * Access every hardened item's plaintext in a single callback. All {@code char[]}
     * values are zeroed when the callback returns or throws.
     *
     * <p><b>Fail-fast contract:</b> if any single item fails to decrypt (wrong pepper,
     * tampered envelope, stale epoch, &hellip;) the method returns
     * {@link Optional#empty()} and never invokes the callback -- it does <i>not</i> hand
     * you a silently-truncated map.</p>
     *
     * @apiNote same plaintext-escape warning as {@link #withSecret} applies to every
     *          value in the map. Non-hardened items in the collection are filtered out
     *          before iteration; they are invisible to this API.
     */
    <R> Optional<R> withSecrets(Function<Map<String, char[]>, R> callback);

    boolean deleteItem(String objectPath);

    /** Rotate the collection epoch: rewrap every hardened item under a fresh epoch id. */
    boolean rotateEpoch();

    /** Current runtime status: epoch, time binding, threat coverage, algorithms. */
    HardenedStatus status();

    @Override
    void close();
}
