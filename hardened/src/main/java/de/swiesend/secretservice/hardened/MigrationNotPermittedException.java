package de.swiesend.secretservice.hardened;

/**
 * Thrown by {@code HardenedCollection#migrateNonHardenedToHardened} when the operation has not been
 * enabled through <b>both</b> of its gates: {@code Builder.allowMigration(true)} in code and the
 * {@code SECRET_SERVICE_HARDENED_ALLOW_MIGRATION=1} environment variable at run time.
 *
 * <p>Migration rewrites items the hardened layer did not create -- reading each plaintext item,
 * re-writing it sealed, and deleting the original. In a shared collection (the user's default
 * keyring, typically) that touches data belonging to other applications, and it is not reversible
 * without the pepper. The two gates are deliberately of different kinds so that neither a code
 * change nor a deployment setting can enable it alone: the builder flag is an explicit decision by
 * the author, the environment variable an explicit decision by whoever runs it.</p>
 *
 * <p>This is a refusal to act, not a failure: nothing has been read, written or deleted when it is
 * thrown. It is unrelated to {@link SameUidExposureException}, which concerns key-material
 * strength.</p>
 */
public class MigrationNotPermittedException extends IllegalStateException {
    public MigrationNotPermittedException(String message) { super(message); }
}
