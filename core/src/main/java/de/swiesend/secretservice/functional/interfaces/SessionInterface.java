package de.swiesend.secretservice.functional.interfaces;

import de.swiesend.secretservice.Failure;
import de.swiesend.secretservice.Result;
import de.swiesend.secretservice.TransportEncryption;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SessionInterface extends AutoCloseable {

    Optional<CollectionInterface> collection(String label, Optional<CharSequence> maybePassword);

    Optional<CollectionInterface> collectionById(String id);

    Optional<CollectionInterface> defaultCollection();

    /**
     * As {@link #defaultCollection()}, but answering why there is no default collection to open:
     * {@code NO_DEFAULT_COLLECTION} when the provider names none, where {@code defaultCollection()}
     * answers a collection on which every read and {@code CreateItem} fails.
     *
     * <p>The default body cannot tell: it answers {@code OTHER} when {@code defaultCollection()}
     * answers empty. It keeps an implementation that does not declare this method compiling.</p>
     *
     * @since 4.0.0
     */
    default Result<CollectionInterface> defaultCollectionChecked() {
        return defaultCollection()
                .map(Result::ok)
                .orElseGet(() -> Result.failed(Failure.Reason.OTHER,
                        "No default collection, and this session does not say why"));
    }

    /**
     * The provider's default collection, created with this label when the provider names none. The
     * provider may ask the user first: gnome-keyring asks for the new keyring's password. Never an
     * existing collection in place of the default, not even gnome-keyring's {@code session}, whose
     * secrets live only until the user logs out.
     *
     * <p>The default body creates nothing: it answers {@code OTHER}. It keeps an implementation that
     * does not declare this method compiling.</p>
     *
     * @param label the label of the collection to create, when the provider names no default
     * @return the default collection; {@code DISMISSED} when the user dismissed the dialog,
     *         {@code TIMED_OUT} when nobody answered it, or the failure of a call
     * @throws IllegalArgumentException if {@code label} is null or blank
     * @since 4.0.0
     */
    default Result<CollectionInterface> createDefaultCollection(String label) {
        return Result.failed(Failure.Reason.OTHER, "This session cannot create the default collection");
    }

    TransportEncryption.EncryptedSession getEncryptedSession();

    ServiceInterface getService();

    de.swiesend.secretservice.Session getSession();

    List<CollectionInterface> getCollections();

    UUID getId();

}
