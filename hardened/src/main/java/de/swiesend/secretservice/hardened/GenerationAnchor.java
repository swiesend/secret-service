package de.swiesend.secretservice.hardened;

/**
 * Anti-rollback anchor for the {@link EpochKeystore} generation counter.
 *
 * <p>The keystore stamps a monotonically increasing {@code generation} into every persisted
 * snapshot and, on load, picks the highest generation among the decryptable candidates. That
 * alone defeats a crash that leaves a stale duplicate, but it does <b>not</b> defend against an
 * attacker with write access to the keyring store who deletes the current keystore item and
 * re-introduces a genuine <i>older</i> generation they captured earlier: highest-of-what's-present
 * would happily load the stale snapshot and resurrect epoch keys that a rotation
 * destroyed, silently undoing forward secrecy.</p>
 *
 * <p>A {@code GenerationAnchor} closes that gap by holding the highest generation ever committed in
 * storage the attacker cannot roll back -- a TPM NV <b>monotonic counter</b> is the canonical
 * backing (it can be incremented but never decremented, even by an owner). The keystore treats
 * {@link #read()} as a floor: a loaded snapshot whose generation is below the floor is refused
 * (fail-closed), so a rollback is detected rather than honoured.</p>
 *
 * <h3>Contract</h3>
 * <ul>
 *   <li>{@link #read()} returns the current anchored value. It must be non-decreasing across the
 *       lifetime of the backing store -- once a value has been observed, a later {@code read()}
 *       must never return something smaller.</li>
 *   <li>{@link #advanceTo(long)} raises the anchor to at least {@code target} and returns the new
 *       value ({@code >= target}). It is idempotent when the anchor already meets {@code target}.
 *       The keystore calls it <b>after</b> a new snapshot is durably written (write-ahead), so a
 *       crash between the write and the advance is recoverable: the next load sees a generation
 *       above the floor and catches the anchor up.</li>
 *   <li>Advancing must be authenticated (e.g. a TPM auth value) so a hostile process cannot push
 *       the floor past the live keystore and cause a fail-closed denial of service. Reading may be
 *       unauthenticated.</li>
 * </ul>
 *
 * <p>The generation lives in the anchor's value space (the keystore seeds it from {@link #read()}),
 * so enable the anchor when a collection is <b>created</b>. Retrofitting it onto an existing
 * non-anchored keystore whose small generation sits below a freshly provisioned counter will be
 * refused as a rollback -- provision a fresh counter and rotate instead.</p>
 *
 * <h3>One anchor per collection</h3>
 * <p><b>An anchor must back exactly one collection.</b> The floor is global but each collection
 * keeps its own generation seeded from it, so two collections sharing an anchor ping-pong: whichever
 * persisted last sits above the floor and pushes the other below it, which is then refused as a
 * rollback and fails closed on reads <em>and</em> writes -- both collections end up bricked. The
 * builder detects this via {@link #scopeKey()} and refuses to construct the second collection rather
 * than let it happen at runtime. Provision one NV counter per collection.</p>
 */
public interface GenerationAnchor extends AutoCloseable {

    /** The current anchored floor: the highest generation durably committed. Non-decreasing. */
    long read();

    /**
     * Raise the anchor to at least {@code target}; returns the resulting value ({@code >= target}).
     * A no-op that returns the current value when it is already {@code >= target}.
     */
    long advanceTo(long target);

    /**
     * Identity of the underlying counter, used to detect two collections sharing one anchor (see
     * "One anchor per collection" above).
     *
     * <p>The default is the instance itself, which catches the common case of injecting the same
     * object twice. Implementations backed by named external storage should override it with a
     * value derived from that name -- {@code Tpm2GenerationAnchor} returns its NV index -- so that
     * two <em>distinct</em> objects pointing at the same counter are caught too. The returned value
     * must implement {@code equals}/{@code hashCode} by value.</p>
     */
    default Object scopeKey() { return this; }

    /** Release any held resources (open TPM handle, cached auth). Default no-op. */
    @Override
    default void close() {}
}
