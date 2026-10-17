package de.swiesend.secretservice.hardened;

/**
 * Thrown by {@code HardenedCollection#migrateNonHardenedToHardened} when the migration could not
 * establish what there was to migrate -- the collection's item enumeration failed, so the set of
 * candidates is unknown.
 *
 * <p>Why this is not a report: a {@code MigrationReport} describes an <b>outcome</b> -- so many
 * considered, migrated, skipped, failed. Returning {@code considered=0, migrated=0, failed=0} for
 * an enumeration that never answered describes an outcome that did not happen, and reads exactly
 * like the legitimate "there was nothing to migrate". An operator running this one-shot command
 * during a daemon hiccup would conclude the collection is fully hardened and leave plaintext items
 * behind, with nothing in the report to suggest otherwise.</p>
 *
 * <p>Like {@link MigrationNotPermittedException} this is raised before anything is read, written or
 * deleted; unlike it, the operation was permitted and simply could not proceed. Retrying once the
 * provider answers again is the expected response.</p>
 *
 * @see de.swiesend.secretservice.functional.interfaces.CollectionInterface#getItems(java.util.Map)
 */
public class MigrationFailedException extends IllegalStateException {
    public MigrationFailedException(String message) { super(message); }
}
